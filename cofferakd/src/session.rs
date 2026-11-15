//! One client connection's protocol state, shared by the Unix socket and
//! TLS listeners (ADR 0019).
//!
//! A connection starts in protocol version 1: every line is a complete
//! request carrying its own token. A client that sends `Hello` first
//! switches the connection to version 2: it authenticates once, then sends
//! requests without a token, may ask for many values in one request, and
//! may keep the connection open between requests.
//!
//! A version 2 session keeps the credential it authenticated with and
//! presents it to the daemon again on every request, so a session never
//! outlives its access: a service removed from the vault, or a token that
//! was replaced, is denied on the very next request, exactly as in
//! version 1.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

use crate::daemon::Daemon;
use crate::protocol::{
    decode_request, decode_request_v2, respond, respond_v2, BatchItem, Request, RequestV2,
    Response, ResponseV2, FEATURES, MAX_BATCH_BYTES, MAX_BATCH_PATHS, PROTOCOL_VERSION,
};

/// Wrong credentials one connection may present before it is closed.
const MAX_FAILED_AUTHS: u32 = 3;

/// How long an authenticated session may stay open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// Longest pause between two requests.
    pub idle: Duration,
    /// Longest total lifetime, however busy the session is.
    pub lifetime: Duration,
}

impl SessionLimits {
    pub const DEFAULT_IDLE_SECS: u64 = 300;
    pub const DEFAULT_LIFETIME_SECS: u64 = 3600;

    /// Limits from `$COFFERAK_SESSION_IDLE_SECS` and
    /// `$COFFERAK_SESSION_MAX_SECS` (whole seconds, at least 1), read once.
    pub fn from_env() -> SessionLimits {
        static LIMITS: OnceLock<SessionLimits> = OnceLock::new();
        *LIMITS.get_or_init(|| SessionLimits {
            idle: Duration::from_secs(parse_secs(
                std::env::var("COFFERAK_SESSION_IDLE_SECS").ok().as_deref(),
                Self::DEFAULT_IDLE_SECS,
            )),
            lifetime: Duration::from_secs(parse_secs(
                std::env::var("COFFERAK_SESSION_MAX_SECS").ok().as_deref(),
                Self::DEFAULT_LIFETIME_SECS,
            )),
        })
    }
}

/// A positive number of seconds, or `default` when unset or not one.
fn parse_secs(raw: Option<&str>, default: u64) -> u64 {
    match raw.map(str::trim).map(str::parse::<u64>) {
        Some(Ok(n)) if n > 0 => n,
        Some(_) => {
            eprintln!("cofferakd: ignoring an invalid session time limit, using {default}s");
            default
        }
        None => default,
    }
}

/// What to send back for one request line.
pub struct Reply {
    /// The encoded response line. The caller wipes it after sending.
    pub bytes: Vec<u8>,
    /// Close the connection after sending.
    pub close: bool,
}

/// Protocol state of one connection.
#[derive(Default)]
pub struct Session {
    v2: bool,
    credential: Option<Zeroizing<String>>,
    failed_auths: u32,
}

impl Session {
    pub fn new() -> Session {
        Session::default()
    }

    /// Whether this connection holds an authenticated version 2 session.
    /// The listeners use it to move the connection from the short
    /// per-connection deadline to the session limits.
    pub fn is_authenticated(&self) -> bool {
        self.credential.is_some()
    }

    /// Handle one request line. `cert_names` is the TLS client
    /// certificate's names when the listener binds tokens to certificates
    /// (ADR 0017), `None` on the Unix socket.
    pub fn handle_line(
        &mut self,
        line: &[u8],
        daemon: &Mutex<Daemon>,
        cert_names: Option<&[String]>,
    ) -> Reply {
        if !self.v2 {
            if let Ok(req) = decode_request(line) {
                return reply(respond(dispatch(daemon, req, cert_names)));
            }
            return match decode_request_v2(line) {
                Ok(RequestV2::Hello { version }) if version >= 2 => {
                    self.v2 = true;
                    reply_v2(ResponseV2::Hello {
                        version: PROTOCOL_VERSION,
                        features: FEATURES.iter().map(|f| f.to_string()).collect(),
                    })
                }
                Ok(RequestV2::Hello { .. }) => {
                    reply_v2(ResponseV2::Err("unsupported protocol version".into()))
                }
                _ => reply(respond(Response::Err("malformed request".into()))),
            };
        }

        let req = match decode_request_v2(line) {
            Ok(req) => req,
            Err(_) => return reply_v2(ResponseV2::Err("malformed request".into())),
        };
        match req {
            RequestV2::Hello { .. } => reply_v2(ResponseV2::Err("session is already open".into())),
            RequestV2::Ping => reply_v2(ResponseV2::Ok),
            RequestV2::Auth { method, credential } => {
                let credential = Zeroizing::new(credential);
                self.authenticate(&method, credential, daemon, cert_names)
            }
            other => {
                let Some(token) = self.credential.as_ref().map(|c| c.to_string()) else {
                    return reply_v2(ResponseV2::Err("authenticate first".into()));
                };
                let token = Zeroizing::new(token);
                reply_v2(run(daemon, &token, other, cert_names))
            }
        }
    }

    fn authenticate(
        &mut self,
        method: &str,
        credential: Zeroizing<String>,
        daemon: &Mutex<Daemon>,
        cert_names: Option<&[String]>,
    ) -> Reply {
        if method != "token" {
            return reply_v2(ResponseV2::Err(format!(
                "unsupported authentication method {:?}",
                crate::daemon::audit_safe(method)
            )));
        }
        let service = lock(daemon).authenticate(&credential, cert_names);
        match service {
            Some(service) => {
                self.credential = Some(credential);
                self.failed_auths = 0;
                reply_v2(ResponseV2::Authed { service })
            }
            None => {
                self.credential = None;
                self.failed_auths += 1;
                Reply {
                    bytes: respond_v2(ResponseV2::Denied),
                    close: self.failed_auths >= MAX_FAILED_AUTHS,
                }
            }
        }
    }
}

fn reply(bytes: Vec<u8>) -> Reply {
    Reply {
        bytes,
        close: false,
    }
}

fn reply_v2(response: ResponseV2) -> Reply {
    reply(respond_v2(response))
}

fn lock(daemon: &Mutex<Daemon>) -> std::sync::MutexGuard<'_, Daemon> {
    daemon
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run one version 1 request against the daemon.
fn dispatch(daemon: &Mutex<Daemon>, req: Request, cert_names: Option<&[String]>) -> Response {
    let mut d = lock(daemon);
    match cert_names {
        Some(names) => d.handle_request_for_certificate(req, names),
        None => d.handle_request(req),
    }
}

/// Run one authenticated version 2 request. Each is carried out as the
/// matching version 1 request with the session's credential, so access
/// control, certificate binding, persistence and the audit log are the
/// same code for both versions.
fn run(
    daemon: &Mutex<Daemon>,
    token: &str,
    req: RequestV2,
    cert_names: Option<&[String]>,
) -> ResponseV2 {
    let token = || token.to_string();
    match req {
        RequestV2::Get { path } => to_v2(dispatch(
            daemon,
            Request::Get {
                token: token(),
                path,
            },
            cert_names,
        )),
        RequestV2::Set { path, value } => {
            let mut value = value;
            let decoded = B64.decode(value.as_bytes());
            value.zeroize();
            match decoded {
                Ok(value) => to_v2(dispatch(
                    daemon,
                    Request::Set {
                        token: token(),
                        path,
                        value,
                    },
                    cert_names,
                )),
                Err(_) => ResponseV2::Err("value is not valid base64".into()),
            }
        }
        RequestV2::Rm { path } => to_v2(dispatch(
            daemon,
            Request::Rm {
                token: token(),
                path,
            },
            cert_names,
        )),
        RequestV2::List { prefix } => to_v2(dispatch(
            daemon,
            Request::List {
                token: token(),
                prefix,
            },
            cert_names,
        )),
        RequestV2::GetMany { paths } => get_many(daemon, token, paths, cert_names),
        // Handled by the caller before authentication is required.
        RequestV2::Hello { .. } | RequestV2::Auth { .. } | RequestV2::Ping => {
            ResponseV2::Err("malformed request".into())
        }
    }
}

/// Read many values under one lock of the daemon, so the batch is one
/// consistent view of the vault. Each path is checked and audited on its
/// own: a path the session may not read is reported as `denied` without
/// failing the paths it may read.
fn get_many(
    daemon: &Mutex<Daemon>,
    token: impl Fn() -> String,
    paths: Vec<String>,
    cert_names: Option<&[String]>,
) -> ResponseV2 {
    if paths.len() > MAX_BATCH_PATHS {
        return ResponseV2::Err(format!(
            "too many paths in one request ({}, limit {MAX_BATCH_PATHS})",
            paths.len()
        ));
    }
    let mut d = lock(daemon);
    let mut items = Vec::with_capacity(paths.len());
    let mut total = 0usize;
    for path in paths {
        let req = Request::Get {
            token: token(),
            path: path.clone(),
        };
        let response = match cert_names {
            Some(names) => d.handle_request_for_certificate(req, names),
            None => d.handle_request(req),
        };
        let (value, error) = match response {
            Response::Value(mut v) => {
                total += v.len();
                let encoded = B64.encode(&v);
                v.zeroize();
                (Some(encoded), None)
            }
            Response::Denied => (None, Some("denied")),
            Response::NotFound => (None, Some("not_found")),
            _ => (None, Some("error")),
        };
        items.push(BatchItem {
            path,
            value,
            error: error.map(str::to_string),
        });
        if total > MAX_BATCH_BYTES {
            for item in &mut items {
                if let Some(v) = item.value.as_mut() {
                    v.zeroize();
                }
            }
            return ResponseV2::Err(format!(
                "values in one request exceed {MAX_BATCH_BYTES} bytes, ask for fewer paths"
            ));
        }
    }
    ResponseV2::Values(items)
}

fn to_v2(response: Response) -> ResponseV2 {
    match response {
        Response::Value(mut v) => {
            let encoded = B64.encode(&v);
            v.zeroize();
            ResponseV2::Value(encoded)
        }
        Response::Listed(paths) => ResponseV2::Listed(paths),
        Response::Ok => ResponseV2::Ok,
        Response::Denied => ResponseV2::Denied,
        Response::NotFound => ResponseV2::NotFound,
        Response::Err(e) => ResponseV2::Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_secs;

    #[test]
    fn session_time_limits_fall_back_on_bad_input() {
        assert_eq!(parse_secs(None, 300), 300);
        assert_eq!(parse_secs(Some("45"), 300), 45);
        assert_eq!(parse_secs(Some("0"), 300), 300);
        assert_eq!(parse_secs(Some("soon"), 300), 300);
    }
}
