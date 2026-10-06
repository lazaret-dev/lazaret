//! Operating-system randomness, with no dependencies.
//!
//! | Platform | Source |
//! |----------|--------|
//! | Linux, Android (x86-64, x86, aarch64, arm) | the `getrandom` system call, called through libc's `syscall` so that old C libraries without the wrapper still link; `/dev/urandom` only if the kernel refuses (before 3.17, or a sandbox that blocks it) |
//! | macOS, iOS, FreeBSD, OpenBSD | `getentropy`, at most 256 bytes per call |
//! | Windows | `BCryptGenRandom` with the system-preferred RNG |
//! | anything else Unix | `/dev/urandom` |
//!
//! Never falls back to a non-cryptographic source: failure is reported to the caller. The
//! `unsafe` blocks here are plain FFI calls into the operating system with a buffer and its
//! length; nothing else in this module is unsafe.

use std::io;

/// Fills `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    os::fill(buf)
}

/// `N` random bytes.
pub fn bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}

/// Reads `/dev/urandom` (the fallback on Unix systems without a better call).
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd"))))]
fn urandom(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

// ------------------------------------------------------------------------------- Linux, Android

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm")
))]
mod os {
    use std::io;

    #[cfg(target_arch = "x86_64")]
    const SYS_GETRANDOM: core::ffi::c_long = 318;
    #[cfg(target_arch = "x86")]
    const SYS_GETRANDOM: core::ffi::c_long = 355;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETRANDOM: core::ffi::c_long = 278;
    #[cfg(target_arch = "arm")]
    const SYS_GETRANDOM: core::ffi::c_long = 384;

    const EPERM: i32 = 1;
    const ENOSYS: i32 = 38;

    extern "C" {
        fn syscall(number: core::ffi::c_long, ...) -> core::ffi::c_long;
    }

    /// One `getrandom(buf, len, 0)` call. Returns the number of bytes written.
    pub(super) fn getrandom_once(buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is valid for writes of `buf.len()` bytes, which is exactly what the
        // kernel is told; flags 0 means "block until the entropy pool is initialised".
        let n = unsafe { syscall(SYS_GETRANDOM, buf.as_mut_ptr(), buf.len(), 0u32) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub(super) fn fill(mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match getrandom_once(buf) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "getrandom returned no data")),
                Ok(n) => buf = &mut buf[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // an old kernel, or a seccomp filter that does not know the call
                Err(e) if matches!(e.raw_os_error(), Some(ENOSYS) | Some(EPERM)) => return super::urandom(buf),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------- macOS and BSD family

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd"))]
mod os {
    use std::io;

    extern "C" {
        fn getentropy(buf: *mut core::ffi::c_void, len: usize) -> core::ffi::c_int;
    }

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        // getentropy refuses requests above 256 bytes.
        for chunk in buf.chunks_mut(256) {
            // SAFETY: `chunk` is valid for writes of `chunk.len()` (at most 256) bytes.
            let rc = unsafe { getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------------------- Windows

#[cfg(windows)]
mod os {
    use std::io;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: *mut core::ffi::c_void, buffer: *mut u8, len: u32, flags: u32) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            // SAFETY: `chunk` is valid for writes of `chunk.len()` bytes; a null algorithm handle
            // together with BCRYPT_USE_SYSTEM_PREFERRED_RNG is the documented way to ask for the
            // system RNG.
            let status = unsafe {
                BCryptGenRandom(core::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            };
            if status != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, format!("BCryptGenRandom failed: {:#x}", status)));
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------ everything else

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd")),
    not(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm")
    ))
))]
mod os {
    use std::io;

    pub(super) fn fill(buf: &mut [u8]) -> io::Result<()> {
        super::urandom(buf)
    }
}

#[cfg(not(any(unix, windows)))]
mod os {
    use std::io;

    pub(super) fn fill(_buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no OS random source available on this platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_nonzero_output() {
        let a: [u8; 32] = bytes().unwrap();
        let b: [u8; 32] = bytes().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn handles_every_size_including_empty_and_larger_than_one_call() {
        // 0 and 1 byte, around the 256-byte getentropy limit, and big enough to need many calls
        for len in [0usize, 1, 31, 255, 256, 257, 511, 512, 1000, 100_000] {
            let mut v = vec![0u8; len];
            fill(&mut v).unwrap();
            if len >= 16 {
                // the chance of 16 or more zero bytes from a working generator is negligible
                assert!(v.iter().any(|&b| b != 0), "len {}", len);
                // every 256-byte block must have been filled, not only the first
                for chunk in v.chunks(256).filter(|c| c.len() >= 16) {
                    assert!(chunk.iter().any(|&b| b != 0), "a chunk of {} bytes stayed zero (len {})", chunk.len(), len);
                }
            }
        }
    }

    #[test]
    fn output_looks_uniform() {
        // a crude sanity check, not a statistical test suite: every byte value should appear
        // in 256 KiB, and the bit counts should sit near one half
        let mut v = vec![0u8; 256 * 1024];
        fill(&mut v).unwrap();
        let mut seen = [false; 256];
        v.iter().for_each(|&b| seen[b as usize] = true);
        assert!(seen.iter().all(|&s| s));
        let ones: u64 = v.iter().map(|b| b.count_ones() as u64).sum();
        let total = v.len() as u64 * 8;
        assert!((ones as f64 / total as f64 - 0.5).abs() < 0.01, "{} of {} bits set", ones, total);
    }

    #[test]
    fn works_from_many_threads() {
        let handles: Vec<_> = (0..8).map(|_| std::thread::spawn(|| bytes::<32>().unwrap())).collect();
        let mut all: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 8);
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd"))))]
    #[test]
    fn urandom_fallback_works() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        urandom(&mut a).unwrap();
        urandom(&mut b).unwrap();
        assert_ne!(a, b);
    }

    /// The system call number and calling convention are right for this architecture: the kernel
    /// accepted the call and filled the buffer (so it did not fall back silently to /dev/urandom).
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64", target_arch = "arm")
    ))]
    #[test]
    fn getrandom_system_call_itself_works() {
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        let n = os::getrandom_once(&mut a).expect("getrandom syscall failed (kernel older than 3.17, or blocked?)");
        assert!(n > 0 && n <= 48);
        assert!(a[..n].iter().any(|&x| x != 0));
        os::getrandom_once(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
