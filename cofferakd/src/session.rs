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

use cofferak_core::workload::Principal;

use crate::daemon::Daemon;
use crate::protocol::{
    decode_request, decode_request_v2, respond, respond_v2, BatchItem, Request, RequestV2,
    Response, ResponseV2, FEATURES, MAX_BATCH_BYTES, MAX_BATCH_PATHS, PROTOCOL_VERSION,
};

/// Current time as Unix seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

    /// How long a session may last: the maximum lifetime, or less when the
    /// identity token it authenticated with expires sooner.
    pub fn lifetime_for(&self, identity_expires_at: Option<i64>) -> Duration {
        match identity_expires_at {
            Some(exp) => {
                let left = exp.saturating_sub(now_unix()).max(0) as u64;
                self.lifetime.min(Duration::from_secs(left))
            }
            None => self.lifetime,
        }
    }

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

/// What an authenticated session acts as.
enum Credential {
    /// A service's own token, presented again on every request.
    Token(Zeroizing<String>),
    /// A workload whose identity token (a JWT) was verified when the
    /// session began, ADR 0022. The token itself is not kept: the daemon
    /// re-checks the binding and the token's expiry on every request.
    Identity(Box<Principal>),
}

/// Protocol state of one connection.
#[derive(Default)]
pub struct Session {
    v2: bool,
    credential: Option<Credential>,
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

    /// When the identity token this session authenticated with expires
    /// (Unix seconds), `None` for a session that used a service token.
    /// The listeners end the session then, if not sooner.
    pub fn identity_expires_at(&self) -> Option<i64> {
        match &self.credential {
            Some(Credential::Identity(who)) => Some(who.expires_at),
            _ => None,
        }
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
                let Some(credential) = &self.credential else {
                    return reply_v2(ResponseV2::Err("authenticate first".into()));
                };
                // A workload's token has run out: close the connection
                // without an answer, the way an idle session ends. A client
                // that holds a fresh token reconnects and authenticates
                // again, one that does not is out.
                if let Credential::Identity(who) = credential {
                    if now_unix() >= who.expires_at {
                        return Reply {
                            bytes: Vec::new(),
                            close: true,
                        };
                    }
                }
                reply_v2(run(daemon, credential, other, cert_names))
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
        let outcome = match method {
            "token" => lock(daemon)
                .authenticate(&credential, cert_names)
                .map(|service| (service, Credential::Token(credential)))
                .ok_or("unknown token"),
            "jwt" => lock(daemon)
                .authenticate_jwt(&credential, cert_names)
                .map(|who| (who.service.clone(), Credential::Identity(Box::new(who)))),
            _ => {
                return reply_v2(ResponseV2::Err(format!(
                    "unsupported authentication method {:?}",
                    crate::daemon::audit_safe(method)
                )));
            }
        };
        match outcome {
            Ok((service, credential)) => {
                self.credential = Some(credential);
                self.failed_auths = 0;
                reply_v2(ResponseV2::Authed { service })
            }
            // The client is only told "denied", the reason is in the audit log.
            Err(_) => {
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

/// Run one request as the session's credential: a service token goes the
/// version 1 way, an identity through the daemon's identity entry point.
fn dispatch_as(
    daemon: &Mutex<Daemon>,
    credential: &Credential,
    req: Request,
    cert_names: Option<&[String]>,
) -> Response {
    match credential {
        Credential::Token(_) => dispatch(daemon, req, cert_names),
        Credential::Identity(who) => lock(daemon).handle_request_for_identity(req, who, cert_names),
    }
}

/// Run one authenticated version 2 request. Each is carried out as the
/// matching version 1 request with the session's credential, so access
/// control, certificate binding, persistence and the audit log are the
/// same code for both versions.
fn run(
    daemon: &Mutex<Daemon>,
    credential: &Credential,
    req: RequestV2,
    cert_names: Option<&[String]>,
) -> ResponseV2 {
    // The token a version 1 request carries. An identity has none, the
    // daemon ignores the field for it.
    let token = || match credential {
        Credential::Token(t) => t.to_string(),
        Credential::Identity(_) => String::new(),
    };
    let dispatch = |req: Request| dispatch_as(daemon, credential, req, cert_names);
    match req {
        RequestV2::Get { path } => to_v2(dispatch(Request::Get {
            token: token(),
            path,
        })),
        RequestV2::Set { path, value } => {
            let mut value = value;
            let decoded = B64.decode(value.as_bytes());
            value.zeroize();
            match decoded {
                Ok(value) => to_v2(dispatch(Request::Set {
                    token: token(),
                    path,
                    value,
                })),
                Err(_) => ResponseV2::Err("value is not valid base64".into()),
            }
        }
        RequestV2::Rm { path } => to_v2(dispatch(Request::Rm {
            token: token(),
            path,
        })),
        RequestV2::List { prefix } => to_v2(dispatch(Request::List {
            token: token(),
            prefix,
        })),
        RequestV2::GetMany { paths } => get_many(daemon, credential, paths, cert_names),
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
    credential: &Credential,
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
            token: match credential {
                Credential::Token(t) => t.to_string(),
                Credential::Identity(_) => String::new(),
            },
            path: path.clone(),
        };
        let response = match credential {
            Credential::Token(_) => match cert_names {
                Some(names) => d.handle_request_for_certificate(req, names),
                None => d.handle_request(req),
            },
            Credential::Identity(who) => d.handle_request_for_identity(req, who, cert_names),
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
