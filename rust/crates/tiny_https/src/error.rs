//! Error type of the `net` side of the library (TLS, HTTP, sockets). Errors from the verification
//! part ([`crate::verify_error`]) are wrapped in [`Error::Verify`]; `?` converts them.

use crate::verify_error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Underlying socket or file I/O failure.
    Io(std::io::Error),
    /// TLS protocol violation or handshake failure.
    Tls(String),
    /// The peer sent an alert.
    Alert(u8, u8),
    /// HTTP-level failure (bad URL, malformed response, too many redirects...).
    Http(String),
    /// Certificate, ASN.1 or revocation checking failed (the verification part of the crate).
    Verify(verify_error::Error),
    /// The client refused to send a request, or a redirect it was following, to where it was going, by its own rules and before it connected
    /// to anything: not a network failure, and not a bad server. See [`Refused`].
    Refused(Refused),
}

/// A request or a redirect that the client's rules did not allow: nothing was sent to the host it named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// 0 if the request itself was refused, 1 for the first redirect it was sent on, and so on.
    pub hop: usize,
    /// Which rule said no.
    pub by: RefusedBy,
    /// Why, in words (it names the host, never a credential, a header value or the path of the URL).
    pub reason: String,
}

/// The rule that refused a request or a redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusedBy {
    /// The rule about hosts of [`Client::allowed_hosts`](crate::http::Client::allowed_hosts).
    HostRule,
    /// A limit on the URL of [`Client::url_limits`](crate::http::Client::url_limits) (its length, its characters, credentials in it, a scheme).
    UrlLimit,
    /// The scheme: plain http without `allow_insecure_http`, or a redirect from https to plain http.
    Scheme,
    /// The hook of [`Client::hop_headers`](crate::http::Client::hop_headers) said no.
    Hook,
}

impl Refused {
    /// Whether this is a redirect that was refused (not the request the caller made).
    pub fn is_redirect(&self) -> bool {
        self.hop > 0
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hop == 0 {
            write!(f, "request refused: {}", self.reason)
        } else {
            write!(f, "redirect {} refused: {}", self.hop, self.reason)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Tls(m) => write!(f, "TLS error: {}", m),
            Error::Alert(level, desc) => write!(f, "TLS alert received (level {}, description {})", level, desc),
            Error::Http(m) => write!(f, "HTTP error: {}", m),
            Error::Verify(e) => e.fmt(f),
            Error::Refused(r) => r.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<verify_error::Error> for Error {
    fn from(e: verify_error::Error) -> Self {
        Error::Verify(e)
    }
}

pub(crate) fn cert<T>(msg: impl Into<String>) -> Result<T> {
    Err(verify_error::Error::Certificate(msg.into()).into())
}
