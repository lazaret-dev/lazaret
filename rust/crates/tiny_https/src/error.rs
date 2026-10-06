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
