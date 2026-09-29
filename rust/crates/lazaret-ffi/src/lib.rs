//! The C ABI of Lazaret's native engine: the only `unsafe` code of the
//! project, and all of it in this file.
//!
//! One call carries everything: a request buffer
//!
//! ```text
//! [u32 LE name length][name, UTF-8][u32 LE args length][args, JSON][text]
//! ```
//!
//! where the text is the rest of the buffer, a Python str encoded as UTF-8
//! with surrogates passed through (Python: `s.encode("utf-8",
//! "surrogatepass")`; the npm package writes the same from a JS string, lone
//! surrogates included). The answer is JSON (ASCII) in a buffer the engine
//! allocates and the caller hands back to `lazaret_engine_free`.
//!
//! Native builds export `lazaret_engine_call`, read by Python's ctypes
//! (lazaret/scanner/_native.py). WebAssembly builds (wasm32-unknown-unknown,
//! loaded by Node's built-in WebAssembly: js/src/lib/native.js) export
//! `lazaret_alloc`, `lazaret_call` and `lazaret_free` instead, the same
//! request and answer in the module's memory. A panic never crosses the
//! boundary: it is caught and reported as status 3.

use lazaret_engine::api::{self, CallError};
use lazaret_engine::json::{self, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const STATUS_OK: i32 = 0;
pub const STATUS_ERROR: i32 = 1;
pub const STATUS_EXHAUSTED: i32 = 2;
pub const STATUS_PANIC: i32 = 3;

/// UTF-8 with surrogates passed through (CPython's "surrogatepass"): the
/// code points of a Python str. None for bytes no such encoder writes.
pub fn decode_wtf8(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as u32;
        if c < 0x80 {
            out.push(c);
            i += 1;
            continue;
        }
        let (n, min, init) = if c & 0xE0 == 0xC0 {
            (1, 0x80, c & 0x1F)
        } else if c & 0xF0 == 0xE0 {
            (2, 0x800, c & 0x0F)
        } else if c & 0xF8 == 0xF0 {
            (3, 0x10000, c & 0x07)
        } else {
            return None;
        };
        let mut v = init;
        for k in 1..=n {
            let x = *b.get(i + k)? as u32;
            if x & 0xC0 != 0x80 {
                return None;
            }
            v = (v << 6) | (x & 0x3F);
        }
        if v < min || v > 0x10FFFF {
            return None;
        }
        out.push(v);
        i += n + 1;
    }
    Some(out)
}

fn read_u32(b: &[u8], at: usize) -> Option<usize> {
    let w = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as usize)
}

/// Run one request: (status, JSON answer).
pub fn handle(req: &[u8]) -> (i32, String) {
    let r = catch_unwind(AssertUnwindSafe(|| handle_inner(req)));
    match r {
        Ok(v) => v,
        Err(_) => (STATUS_PANIC, json::write(&Value::obj(vec![("error", Value::str("panic in the native engine"))]))),
    }
}

fn error(status: i32, msg: &str) -> (i32, String) {
    (status, json::write(&Value::obj(vec![("error", Value::str(msg))])))
}

fn handle_inner(req: &[u8]) -> (i32, String) {
    let parsed = (|| {
        let nlen = read_u32(req, 0)?;
        let name = std::str::from_utf8(req.get(4..4 + nlen)?).ok()?;
        let alen = read_u32(req, 4 + nlen)?;
        let astart = 8 + nlen;
        let args = std::str::from_utf8(req.get(astart..astart + alen)?).ok()?;
        let text = req.get(astart + alen..)?;
        Some((name, args, text))
    })();
    let (name, args, text) = match parsed {
        Some(p) => p,
        None => return error(STATUS_ERROR, "malformed request"),
    };
    let args = if args.is_empty() {
        Value::Obj(Vec::new())
    } else {
        match json::parse_str(args) {
            Ok(v) => v,
            Err(e) => return error(STATUS_ERROR, &format!("bad arguments: {}", e.0)),
        }
    };
    let text = match decode_wtf8(text) {
        Some(t) => t,
        None => return error(STATUS_ERROR, "text is not UTF-8"),
    };
    match api::call(name, &args, &text) {
        Ok(v) => (STATUS_OK, json::write(&v)),
        Err(CallError::Exhausted) => error(STATUS_EXHAUSTED, "work budget spent"),
        Err(CallError::Unknown(n)) => error(STATUS_ERROR, &format!("unknown call {}", n)),
        Err(CallError::BadArgs(m)) => error(STATUS_ERROR, &m),
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;

    /// The engine's version, NUL-terminated (static).
    #[no_mangle]
    pub extern "C" fn lazaret_engine_version() -> *const u8 {
        concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr()
    }

    /// Run one request (see the module docs). The answer is written to
    /// `*out` / `*out_len`, to be released with `lazaret_engine_free`.
    ///
    /// # Safety
    /// `req` points to `req_len` readable bytes; `out` and `out_len` are
    /// writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_engine_call(
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        if req.is_null() || out.is_null() || out_len.is_null() {
            return STATUS_ERROR;
        }
        let request = std::slice::from_raw_parts(req, req_len);
        let (status, answer) = handle(request);
        let boxed: Box<[u8]> = answer.into_bytes().into_boxed_slice();
        let len = boxed.len();
        *out = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
        status
    }

    /// Release an answer of `lazaret_engine_call`.
    ///
    /// # Safety
    /// `p` and `len` are exactly what `lazaret_engine_call` wrote.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_engine_free(p: *mut u8, len: usize) {
        if !p.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;

    /// Room for a request of `len` bytes in the module's memory.
    #[no_mangle]
    pub extern "C" fn lazaret_alloc(len: usize) -> *mut u8 {
        let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
        Box::into_raw(boxed) as *mut u8
    }

    /// Release a buffer of `lazaret_alloc` or `lazaret_call`.
    ///
    /// # Safety
    /// `p` and `len` are a buffer this module handed out.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_free(p: *mut u8, len: usize) {
        if !p.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
        }
    }

    /// Run the request at `req` (`len` bytes, from `lazaret_alloc`; freed
    /// here). Returns a buffer: [u32 LE status][u32 LE length][answer],
    /// released with `lazaret_free(ptr, 8 + length)`.
    ///
    /// # Safety
    /// `req` and `len` are a buffer of `lazaret_alloc`.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_call(req: *mut u8, len: usize) -> *mut u8 {
        let request: Box<[u8]> = Box::from_raw(std::ptr::slice_from_raw_parts_mut(req, len));
        let (status, answer) = handle(&request);
        drop(request);
        let mut buf = Vec::with_capacity(8 + answer.len());
        buf.extend_from_slice(&(status as u32).to_le_bytes());
        buf.extend_from_slice(&(answer.len() as u32).to_le_bytes());
        buf.extend_from_slice(answer.as_bytes());
        Box::into_raw(buf.into_boxed_slice()) as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, args: &str, text: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&(name.len() as u32).to_le_bytes());
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(&(args.len() as u32).to_le_bytes());
        r.extend_from_slice(args.as_bytes());
        r.extend_from_slice(text);
        r
    }

    #[test]
    fn wtf8() {
        assert_eq!(decode_wtf8("a\u{e9}\u{1F600}".as_bytes()), Some(vec![0x61, 0xE9, 0x1F600]));
        assert_eq!(decode_wtf8(&[0xED, 0xA0, 0x80]), Some(vec![0xD800]));
        assert_eq!(decode_wtf8(&[0xC0, 0x80]), None);
        assert_eq!(decode_wtf8(&[0xE2, 0x82]), None);
    }

    #[test]
    fn calls() {
        let (s, a) = handle(&request("version", "", b""));
        assert_eq!(s, STATUS_OK);
        assert!(a.contains("\"rust\""));
        let (s, _) = handle(&request("nope", "{}", b""));
        assert_eq!(s, STATUS_ERROR);
        let (s, _) = handle(b"\xff\xff\xff\xff");
        assert_eq!(s, STATUS_ERROR);
    }
}
