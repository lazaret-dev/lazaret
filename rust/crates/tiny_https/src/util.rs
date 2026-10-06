//! Small shared helpers (hex, constant-time comparison, byte readers).

pub fn hex(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex digit"),
        })
        .collect();
    assert!(digits.len() % 2 == 0, "odd hex length");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// Constant-time equality for byte strings (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// A cursor over a byte slice with checked, big-endian reads.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
    /// Reads a vector with a 1-byte length prefix.
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// Reads a vector with a 2-byte length prefix.
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// Reads a vector with a 3-byte length prefix.
    pub fn vec24(&mut self) -> Option<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
}
