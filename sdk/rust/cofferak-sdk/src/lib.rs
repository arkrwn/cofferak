//! Minimal Rust client SDK for cofferak.
//!
//! Connects to a running `cofferakd` over either its Unix socket or,
//! since ADR 0008 (server mode), TLS-wrapped TCP - and speaks the same
//! newline-delimited JSON protocol documented in
//! `cofferakd/src/protocol.rs` (`Request`/`Response`). This crate does not
//! depend on `cofferakd` or `cofferak-core` - it reimplements just the wire
//! format, so it stays usable as a standalone dependency for any Rust
//! service that wants to read/write secrets without shelling out to the
//! `cofferak` CLI binary.
//!
//! ```no_run
//! use cofferak_sdk::Client;
//!
//! let client = Client::connect("/run/cofferak/cofferakd.sock");
//! client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t").unwrap();
//! let value = client.get("my-token", "myapp/DB_PASSWORD").unwrap();
//! assert_eq!(value, b"s3cr3t");
//! ```
//!
//! Sessions (protocol version 2): authenticate once, keep one connection,
//! and read many values in one round trip.
//!
//! ```no_run
//! use cofferak_sdk::Client;
//!
//! let client = Client::connect("/run/cofferak/cofferakd.sock");
//! let mut session = client.session("my-token").unwrap();
//! let password = session.get("myapp/DB_PASSWORD").unwrap();
//! let config = session.get_all("myapp").unwrap(); // path -> value
//! ```

use serde::{Deserialize, Serialize};
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Errors a client call can return. Mirrors the daemon's response taxonomy
/// (`Denied`, `NotFound`, `Err(String)`) plus local I/O/protocol/TLS-setup
/// failures.
#[derive(Debug)]
pub enum SdkError {
    /// The token doesn't have access to this path, or the token is unknown.
    Denied,
    /// The requested path has no value set.
    NotFound,
    /// The daemon returned an error message.
    Remote(String),
    /// A local I/O failure connecting to or reading from the transport.
    Io(std::io::Error),
    /// The daemon's response wasn't valid JSON, or didn't match any known
    /// `Response` shape.
    Protocol(String),
    /// Loading certs/keys or building the TLS config failed (TLS
    /// transport only).
    Tls(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Denied => write!(f, "denied"),
            SdkError::NotFound => write!(f, "not found"),
            SdkError::Remote(msg) => write!(f, "remote error: {msg}"),
            SdkError::Io(e) => write!(f, "io error: {e}"),
            SdkError::Protocol(msg) => write!(f, "protocol error: {msg}"),
            SdkError::Tls(msg) => write!(f, "tls error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SdkError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SdkError {
    fn from(e: std::io::Error) -> Self {
        SdkError::Io(e)
    }
}

/// Wire-format request, matching `cofferakd::protocol::Request` exactly
/// (externally-tagged enum, the default `serde` representation).
#[derive(Serialize)]
enum Request<'a> {
    Get {
        token: &'a str,
        path: &'a str,
    },
    Set {
        token: &'a str,
        path: &'a str,
        value: Vec<u8>,
    },
    Rm {
        token: &'a str,
        path: &'a str,
    },
    List {
        token: &'a str,
        prefix: &'a str,
    },
}

/// Wire-format response, matching `cofferakd::protocol::Response` exactly.
#[derive(Deserialize)]
enum Response {
    Value(Vec<u8>),
    Listed(Vec<String>),
    Ok,
    Denied,
    NotFound,
    Err(String),
}

/// What a TLS handshake negotiated, from [`Client::tls_session_info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionInfo {
    /// e.g. `TLSv1_3`.
    pub protocol_version: String,
    /// e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher_suite: String,
    /// e.g. `MLKEM1024`.
    pub key_exchange_group: String,
}

/// Options for connecting over TLS/TCP (server mode, ADR 0008) instead
/// of the Unix socket.
pub struct TlsOptions {
    /// `host:port` to connect to (matches the daemon's `$COFFERAK_TLS_ADDR`).
    pub addr: String,
    /// The name to verify the server's certificate against (its subject/SAN).
    pub server_name: String,
    /// PEM file containing the CA that signed the server's certificate.
    /// cofferak's TLS is for a self-managed deployment, not the public
    /// web - there is no built-in trust of public root CAs.
    pub ca_cert_path: PathBuf,
    /// Client certificate + private key (PEM). `cofferakd` server mode
    /// always requires mutual TLS (ADR 0011), so a real connection needs
    /// this, it is an `Option` only so a client can be built to prove that
    /// a certificate-less connection is refused.
    pub client_cert_and_key: Option<(PathBuf, PathBuf)>,
}

/// The client TLS settings, identical to `cofferakd`'s server
/// (ADR 0011): AWS-LC, TLS 1.3 only, AES-256-GCM-SHA384 only, key exchange
/// ML-KEM-1024 > X25519MLKEM768 (post-quantum hybrid) > P-384.
fn hardened_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{cipher_suite, default_provider, kx_group};
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            kx_group::MLKEM1024,
            kx_group::X25519MLKEM768,
            kx_group::SECP384R1,
        ],
        ..default_provider()
    }
}

#[derive(Clone)]
enum Transport {
    Unix(PathBuf),
    Tls {
        addr: String,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    },
}

/// A client connected to one cofferakd endpoint - a Unix socket or, since
/// ADR 0008, a TLS/TCP address. Cheap to construct for the Unix case;
/// each call opens a fresh connection either way (matching `cofferakd`'s
/// own CLI client convention: simplest correct option, no
/// connection-pooling complexity).
pub struct Client {
    transport: Transport,
}

/// Hard ceiling on one response line - mirrors
/// `cofferakd::protocol::MAX_LINE_BYTES` (duplicated, not shared: this
/// crate deliberately has no dependency on `cofferakd`/`cofferak-core`, see
/// the module doc comment). A malicious or compromised daemon that
/// never terminates a response otherwise grows this buffer without
/// limit.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Read one newline-delimited line from `reader` into `buf` (cleared
/// first), refusing to grow past [`MAX_LINE_BYTES`]. See
/// `cofferakd::protocol::read_line_bounded` for the identical algorithm
/// and rationale.
fn read_line_bounded<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    buf.clear();
    let mut total = 0usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(total);
        }
        if let Some(newline_at) = available.iter().position(|&b| b == b'\n') {
            if total + newline_at + 1 > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response line exceeded the maximum allowed size",
                ));
            }
            buf.extend_from_slice(&available[..=newline_at]);
            total += newline_at + 1;
            reader.consume(newline_at + 1);
            return Ok(total);
        }
        let chunk_len = available.len();
        if total + chunk_len > MAX_LINE_BYTES {
            reader.consume(chunk_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response line exceeded the maximum allowed size",
            ));
        }
        buf.extend_from_slice(available);
        total += chunk_len;
        reader.consume(chunk_len);
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, SdkError> {
    let file = std::fs::File::open(path)
        .map_err(|e| SdkError::Tls(format!("reading {}: {e}", path.display())))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SdkError::Tls(format!("parsing certs in {}: {e}", path.display())))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, SdkError> {
    let file = std::fs::File::open(path)
        .map_err(|e| SdkError::Tls(format!("reading {}: {e}", path.display())))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|e| SdkError::Tls(format!("parsing private key in {}: {e}", path.display())))?
        .ok_or_else(|| SdkError::Tls(format!("no private key found in {}", path.display())))
}

impl Client {
    /// Build a client for the daemon's socket at `socket_path`. Does not
    /// connect yet - connection happens per call.
    pub fn connect(socket_path: impl AsRef<Path>) -> Self {
        Client {
            transport: Transport::Unix(socket_path.as_ref().to_path_buf()),
        }
    }

    /// Build a client for the daemon's TLS/TCP listener (server mode,
    /// ADR 0008). Loads and validates the CA (and, if given, client
    /// cert/key) eagerly, so a misconfiguration fails here rather than
    /// on the first call.
    pub fn connect_tls(options: TlsOptions) -> Result<Self, SdkError> {
        let ca_certs = load_certs(&options.ca_cert_path)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| SdkError::Tls(format!("adding CA cert: {e}")))?;
        }

        let builder = ClientConfig::builder_with_provider(Arc::new(hardened_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| SdkError::Tls(format!("TLS configuration: {e}")))?
            .with_root_certificates(roots);
        let config = if let Some((cert_path, key_path)) = &options.client_cert_and_key {
            let certs = load_certs(cert_path)?;
            let key = load_private_key(key_path)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| SdkError::Tls(format!("invalid client certificate/key: {e}")))?
        } else {
            builder.with_no_client_auth()
        };

        let server_name = ServerName::try_from(options.server_name)
            .map_err(|e| SdkError::Tls(format!("invalid server name: {e}")))?
            .to_owned();

        Ok(Client {
            transport: Transport::Tls {
                addr: options.addr,
                server_name,
                config: Arc::new(config),
            },
        })
    }

    /// For a TLS client: complete a handshake with the server and report
    /// what was negotiated (protocol version, cipher suite, key-exchange
    /// group), without sending a request. Useful to verify a deployment
    /// actually uses post-quantum key exchange. Returns `None` for a
    /// Unix-socket client.
    pub fn tls_session_info(&self) -> Result<Option<TlsSessionInfo>, SdkError> {
        let Transport::Tls {
            addr,
            server_name,
            config,
        } = &self.transport
        else {
            return Ok(None);
        };
        let mut tcp = TcpStream::connect(addr)?;
        let timeout = Some(std::time::Duration::from_secs(30));
        let _ = tcp.set_read_timeout(timeout);
        let _ = tcp.set_write_timeout(timeout);
        let mut conn = ClientConnection::new(Arc::clone(config), server_name.clone())
            .map_err(|e| SdkError::Tls(format!("starting TLS handshake: {e}")))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp)
                .map_err(|e| SdkError::Tls(format!("TLS handshake: {e}")))?;
        }
        let info = TlsSessionInfo {
            protocol_version: conn
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_default(),
            cipher_suite: conn
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()))
                .unwrap_or_default(),
            key_exchange_group: conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()))
                .unwrap_or_default(),
        };
        conn.send_close_notify();
        let _ = conn.complete_io(&mut tcp);
        Ok(Some(info))
    }

    /// Open a session (protocol version 2): authenticate once with
    /// `token`, then make any number of calls on one connection. Returns
    /// [`SdkError::Denied`] if the token is not accepted and
    /// [`SdkError::Protocol`] if the daemon is too old for sessions.
    pub fn session(&self, token: &str) -> Result<Session, SdkError> {
        let mut session = Session {
            transport: self.transport.clone(),
            token: token.to_string(),
            stream: None,
            service: String::new(),
        };
        session.connect()?;
        Ok(session)
    }

    fn send(&self, request: &Request) -> Result<Response, SdkError> {
        let mut bytes = serde_json::to_vec(request)
            .map_err(|e| SdkError::Protocol(format!("failed to encode request: {e}")))?;
        bytes.push(b'\n');

        let mut line = Vec::new();
        match &self.transport {
            Transport::Unix(socket_path) => {
                let mut stream = UnixStream::connect(socket_path)?;
                stream.write_all(&bytes)?;
                let mut reader = BufReader::new(stream);
                read_line_bounded(&mut reader, &mut line)?;
            }
            Transport::Tls {
                addr,
                server_name,
                config,
            } => {
                let tcp = TcpStream::connect(addr)?;
                // A malicious or hung server otherwise blocks the
                // caller's thread indefinitely - bound it, matching the
                // daemon's own stance on its listeners.
                let timeout = Some(std::time::Duration::from_secs(30));
                let _ = tcp.set_read_timeout(timeout);
                let _ = tcp.set_write_timeout(timeout);
                let conn = ClientConnection::new(Arc::clone(config), server_name.clone())
                    .map_err(|e| SdkError::Tls(format!("starting TLS handshake: {e}")))?;
                let tls = StreamOwned::new(conn, tcp);
                let mut reader = BufReader::new(tls);
                reader.get_mut().write_all(&bytes)?;
                read_line_bounded(&mut reader, &mut line)?;
            }
        }
        let line = String::from_utf8(line)
            .map_err(|e| SdkError::Protocol(format!("response was not valid UTF-8: {e}")))?;

        serde_json::from_str(&line)
            .map_err(|e| SdkError::Protocol(format!("failed to decode response: {e}")))
    }

    fn check_ok(response: Response) -> Result<(), SdkError> {
        match response {
            Response::Ok => Ok(()),
            Response::Denied => Err(SdkError::Denied),
            Response::NotFound => Err(SdkError::NotFound),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to a write/delete request: {other:?}"
            ))),
        }
    }

    /// Read a secret's value.
    pub fn get(&self, token: &str, path: &str) -> Result<Vec<u8>, SdkError> {
        match self.send(&Request::Get { token, path })? {
            Response::Value(bytes) => Ok(bytes),
            Response::Denied => Err(SdkError::Denied),
            Response::NotFound => Err(SdkError::NotFound),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to Get: {other:?}"
            ))),
        }
    }

    /// Write a secret's value. Requires a read-write token.
    pub fn set(&self, token: &str, path: &str, value: &[u8]) -> Result<(), SdkError> {
        let response = self.send(&Request::Set {
            token,
            path,
            value: value.to_vec(),
        })?;
        Self::check_ok(response)
    }

    /// Remove a secret. Requires a read-write token.
    pub fn rm(&self, token: &str, path: &str) -> Result<(), SdkError> {
        let response = self.send(&Request::Rm { token, path })?;
        Self::check_ok(response)
    }

    /// List secret paths under `prefix`.
    pub fn list(&self, token: &str, prefix: &str) -> Result<Vec<String>, SdkError> {
        match self.send(&Request::List { token, prefix })? {
            Response::Listed(paths) => Ok(paths),
            Response::Denied => Err(SdkError::Denied),
            Response::Err(msg) => Err(SdkError::Remote(msg)),
            other => Err(SdkError::Protocol(format!(
                "unexpected response to List: {other:?}"
            ))),
        }
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Value(_) => write!(f, "Value(..)"),
            Response::Listed(v) => write!(f, "Listed({v:?})"),
            Response::Ok => write!(f, "Ok"),
            Response::Denied => write!(f, "Denied"),
            Response::NotFound => write!(f, "NotFound"),
            Response::Err(e) => write!(f, "Err({e:?})"),
        }
    }
}

/// Mirrors `cofferakd::protocol::MAX_BATCH_PATHS`: the most paths one
/// `GetMany` request may carry. [`Session::get_many`] splits longer lists.
const MAX_BATCH_PATHS: usize = 256;

/// Wire-format session request, matching `cofferakd::protocol::RequestV2`.
#[derive(Serialize)]
enum SessionRequest<'a> {
    Hello {
        version: u32,
    },
    Auth {
        method: &'a str,
        credential: &'a str,
    },
    Get {
        path: &'a str,
    },
    GetMany {
        paths: &'a [String],
    },
    Set {
        path: &'a str,
        value: String,
    },
    Rm {
        path: &'a str,
    },
    List {
        prefix: &'a str,
    },
    Ping,
}

#[derive(Deserialize)]
struct BatchItem {
    path: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Wire-format session response, matching `cofferakd::protocol::ResponseV2`.
#[derive(Deserialize)]
enum SessionResponse {
    Hello {
        #[allow(dead_code)]
        version: u32,
    },
    Authed {
        service: String,
    },
    Value(String),
    Values(Vec<BatchItem>),
    Listed(Vec<String>),
    Ok,
    Denied,
    NotFound,
    Err(String),
}

impl SessionResponse {
    /// The error for a response that is not the one a call expected.
    fn into_error(self, what: &str) -> SdkError {
        match self {
            SessionResponse::Denied => SdkError::Denied,
            SessionResponse::NotFound => SdkError::NotFound,
            SessionResponse::Err(msg) => SdkError::Remote(msg),
            _ => SdkError::Protocol(format!("unexpected response to {what}")),
        }
    }
}

enum Stream {
    Unix(BufReader<UnixStream>),
    Tls(Box<BufReader<StreamOwned<ClientConnection, TcpStream>>>),
}

impl Stream {
    fn open(transport: &Transport) -> Result<Stream, SdkError> {
        let timeout = Some(std::time::Duration::from_secs(30));
        match transport {
            Transport::Unix(socket_path) => {
                let stream = UnixStream::connect(socket_path)?;
                let _ = stream.set_read_timeout(timeout);
                let _ = stream.set_write_timeout(timeout);
                Ok(Stream::Unix(BufReader::new(stream)))
            }
            Transport::Tls {
                addr,
                server_name,
                config,
            } => {
                let tcp = TcpStream::connect(addr)?;
                let _ = tcp.set_read_timeout(timeout);
                let _ = tcp.set_write_timeout(timeout);
                let conn = ClientConnection::new(Arc::clone(config), server_name.clone())
                    .map_err(|e| SdkError::Tls(format!("starting TLS handshake: {e}")))?;
                Ok(Stream::Tls(Box::new(BufReader::new(StreamOwned::new(
                    conn, tcp,
                )))))
            }
        }
    }

    /// Send one request line and read one response line.
    fn roundtrip(&mut self, request: &[u8], line: &mut Vec<u8>) -> std::io::Result<()> {
        let read = match self {
            Stream::Unix(reader) => {
                reader.get_mut().write_all(request)?;
                read_line_bounded(reader, line)?
            }
            Stream::Tls(reader) => {
                reader.get_mut().write_all(request)?;
                read_line_bounded(reader.as_mut(), line)?
            }
        };
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "cofferakd closed the connection",
            ));
        }
        Ok(())
    }
}

/// An authenticated connection to cofferakd (protocol version 2), from
/// [`Client::session`].
///
/// One connection carries every call, so over TLS the handshake is paid
/// once instead of once per secret. If the daemon closes the connection
/// (it does after an idle period), the next call reconnects and
/// authenticates again without the caller noticing.
pub struct Session {
    transport: Transport,
    token: String,
    stream: Option<Stream>,
    service: String,
}

impl Session {
    /// The service id the daemon knows this session's token as.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Close the connection. The session reconnects if used again.
    pub fn close(&mut self) {
        self.stream = None;
    }

    fn connect(&mut self) -> Result<(), SdkError> {
        self.stream = Some(Stream::open(&self.transport)?);
        let result = self.handshake();
        if result.is_err() {
            self.stream = None;
        }
        result
    }

    fn handshake(&mut self) -> Result<(), SdkError> {
        match self.roundtrip(&SessionRequest::Hello { version: 2 }) {
            Ok(SessionResponse::Hello { .. }) => {}
            Ok(_) | Err(SdkError::Protocol(_)) => {
                return Err(SdkError::Protocol(
                    "this cofferakd does not support sessions (protocol version 2), \
                     upgrade it or use the per-call Client methods"
                        .to_string(),
                ))
            }
            Err(e) => return Err(e),
        }
        let token = self.token.clone();
        match self.roundtrip(&SessionRequest::Auth {
            method: "token",
            credential: &token,
        })? {
            SessionResponse::Authed { service } => {
                self.service = service;
                Ok(())
            }
            other => Err(other.into_error("Auth")),
        }
    }

    fn roundtrip(&mut self, request: &SessionRequest) -> Result<SessionResponse, SdkError> {
        let mut bytes = serde_json::to_vec(request)
            .map_err(|e| SdkError::Protocol(format!("failed to encode request: {e}")))?;
        bytes.push(b'\n');
        let stream = self.stream.as_mut().ok_or_else(|| {
            SdkError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session is not connected",
            ))
        })?;
        let mut line = Vec::new();
        stream.roundtrip(&bytes, &mut line)?;
        serde_json::from_slice(&line)
            .map_err(|e| SdkError::Protocol(format!("failed to decode response: {e}")))
    }

    /// Send one request. If the connection is gone, reconnect and send it
    /// again once - except when `retry` is false (a request that must not
    /// be repeated), where the connection error is returned.
    fn call(&mut self, request: &SessionRequest, retry: bool) -> Result<SessionResponse, SdkError> {
        if self.stream.is_none() {
            self.connect()?;
        }
        match self.roundtrip(request) {
            Err(SdkError::Io(e)) => {
                self.stream = None;
                if !retry {
                    return Err(SdkError::Io(e));
                }
            }
            other => return other,
        }
        self.connect()?;
        let result = self.roundtrip(request);
        if matches!(result, Err(SdkError::Io(_))) {
            self.stream = None;
        }
        result
    }

    fn decode(value: &str) -> Result<Vec<u8>, SdkError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|e| SdkError::Protocol(format!("value was not valid base64: {e}")))
    }

    /// Read a secret's value.
    pub fn get(&mut self, path: &str) -> Result<Vec<u8>, SdkError> {
        match self.call(&SessionRequest::Get { path }, true)? {
            SessionResponse::Value(value) => Self::decode(&value),
            other => Err(other.into_error("Get")),
        }
    }

    /// Read several secrets in one round trip. Returns the values of the
    /// paths that exist, a path with no value is left out. Returns
    /// [`SdkError::Denied`] if any path is outside what the token may read.
    pub fn get_many(
        &mut self,
        paths: &[String],
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>, SdkError> {
        let mut out = std::collections::BTreeMap::new();
        for chunk in paths.chunks(MAX_BATCH_PATHS) {
            let items = match self.call(&SessionRequest::GetMany { paths: chunk }, true)? {
                SessionResponse::Values(items) => items,
                other => return Err(other.into_error("GetMany")),
            };
            for item in items {
                match (item.error.as_deref(), item.value) {
                    (None, Some(value)) => {
                        out.insert(item.path, Self::decode(&value)?);
                    }
                    (Some("not_found"), _) => {}
                    (Some("denied"), _) => return Err(SdkError::Denied),
                    _ => return Err(SdkError::Remote(format!("could not read {}", item.path))),
                }
            }
        }
        Ok(out)
    }

    /// Read every secret under `prefix`.
    pub fn get_all(
        &mut self,
        prefix: &str,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>, SdkError> {
        let paths = self.list(prefix)?;
        self.get_many(&paths)
    }

    /// Write a secret's value. Requires a read-write token.
    pub fn set(&mut self, path: &str, value: &[u8]) -> Result<(), SdkError> {
        use base64::Engine;
        let value = base64::engine::general_purpose::STANDARD.encode(value);
        match self.call(&SessionRequest::Set { path, value }, true)? {
            SessionResponse::Ok => Ok(()),
            other => Err(other.into_error("Set")),
        }
    }

    /// Remove a secret. Requires a read-write token.
    pub fn rm(&mut self, path: &str) -> Result<(), SdkError> {
        // Not repeated on a lost connection: a second try after a removal
        // that did go through would wrongly report "not found".
        match self.call(&SessionRequest::Rm { path }, false)? {
            SessionResponse::Ok => Ok(()),
            other => Err(other.into_error("Rm")),
        }
    }

    /// List secret paths under `prefix`.
    pub fn list(&mut self, prefix: &str) -> Result<Vec<String>, SdkError> {
        match self.call(&SessionRequest::List { prefix }, true)? {
            SessionResponse::Listed(paths) => Ok(paths),
            other => Err(other.into_error("List")),
        }
    }

    /// Check that the daemon answers on this session.
    pub fn ping(&mut self) -> Result<(), SdkError> {
        match self.call(&SessionRequest::Ping, true)? {
            SessionResponse::Ok => Ok(()),
            other => Err(other.into_error("Ping")),
        }
    }
}
