//! Entry points for the coverage-guided fuzzer in `fuzz/`. Compiled only with
//! `--cfg tiny_https_fuzzing`; not part of the API.
//!
//! Each function takes the raw bytes the fuzzer produced, reads its own settings from the first
//! bytes, and drives the client with the rest. A panic is a finding. Everything is deterministic:
//! the ClientHello's randomness is fixed, so an input reproduces.

use super::conn::ClientConnection;
use super::messages::*;
use super::scripted::*;
use super::suite::*;
use super::*;
use crate::zeroize::Zeroizing;
use crate::x509::TrustStore;

// the fixed ClientHello secrets
const PRIVATE: [u8; 32] = [0x17; 32];
const RANDOM: [u8; 32] = [0x29; 32];
const SESSION_ID: [u8; 32] = [0x3b; 32];

/// 2026-09-15, inside the validity of the fixture certificates.
const NOW: i64 = 1_789_430_400;

fn pick_piece(selector: u8) -> usize {
    [usize::MAX, 1, 2, 5, 17, 64, 300, 1400][(selector % 8) as usize]
}

/// The certificate chain (leaf first) the fuzz seeds use, valid for "example.test" under the trust
/// store in `server_flight`.
pub fn example_chain() -> Vec<Vec<u8>> {
    let der = |p: &str| crate::pem::parse(p).remove(0).data;
    vec![der(include_str!("../../tests/data/leaf_p384.pem")), der(include_str!("../../tests/data/inter_p256.pem"))]
}

fn example_trust() -> TrustStore {
    let mut ts = TrustStore::empty();
    ts.add_der(&crate::pem::parse(include_str!("../../tests/data/root_rsa.pem")).remove(0).data).unwrap();
    ts
}

/// Moves `bytes` into the connection in pieces of `piece` bytes, processing after each, and
/// discards what it produces. Returns false once the connection has failed or is closed.
fn drive(c: &mut ClientConnection, bytes: &[u8], piece: usize) -> bool {
    let mut sink = [0u8; 512];
    for part in bytes.chunks(piece.max(1)) {
        let mut rest = part;
        while !rest.is_empty() {
            while c.has_plaintext() {
                if c.read_plaintext(&mut sink) == 0 {
                    break;
                }
            }
            let space = c.recv_buf();
            let n = space.len().min(rest.len());
            if n == 0 {
                break;
            }
            space[..n].copy_from_slice(&rest[..n]);
            c.recv_filled(n);
            rest = &rest[n..];
            if c.process().is_err() {
                return false;
            }
        }
        let out = c.output().len();
        c.consume_output(out);
        if c.peer_closed() {
            return true;
        }
    }
    while c.has_plaintext() {
        if c.read_plaintext(&mut sink) == 0 {
            break;
        }
    }
    true
}

/// The wire bytes of a correct ServerHello (and compatibility change_cipher_spec) for exactly the
/// client `server_bytes` starts, for the suite `sel % 3`: a seed that gets past the plaintext
/// handshake into the key schedule.
pub fn example_server_hello(sel: u8) -> Vec<u8> {
    let cfg = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
    let c = ClientConnection::start("example.test", &cfg, Zeroizing::new(PRIVATE), &RANDOM, &SESSION_ID);
    let hello = parse_client_hello(c.output()).expect("our own ClientHello parses");
    Session::new(hello, Suite::ALL[(sel % 3) as usize]).hello_records(&ShOpts::default()).0
}

/// The wire bytes of a HelloRetryRequest, the server's compatibility change_cipher_spec and a
/// ServerHello that answers the retried ClientHello with a valid key share (the group's generator
/// point, so it passes validation and reaches the key schedule), for the client `server_bytes`
/// starts. `sel % 3` picks the suite, `sel / 3 % 3` the retry: P-256, P-384 or a cookie only.
pub fn example_hello_retry(sel: u8) -> Vec<u8> {
    use crate::crypto::ecdh;
    use crate::crypto::ecdsa::Curve;
    let suite = Suite::ALL[(sel % 3) as usize];
    let kind = (sel / 3) % 3;
    let (group, cookie): (Option<u16>, Option<&[u8]>) = match kind {
        0 => (Some(GROUP_SECP256R1), None),
        1 => (Some(GROUP_SECP384R1), Some(&[0xc0, 0x0c, 0x1e][..])),
        _ => (None, Some(&[0xc0, 0x0c, 0x1e][..])),
    };
    let hrr = retry_message(&SESSION_ID, suite, group, cookie);
    let (g, public) = match kind {
        0 => (GROUP_SECP256R1, ecdh::public_key(Curve::P256, &[&[0u8; 31][..], &[1]].concat()).unwrap()),
        1 => (GROUP_SECP384R1, ecdh::public_key(Curve::P384, &[&[0u8; 47][..], &[1]].concat()).unwrap()),
        _ => (GROUP_X25519, crate::crypto::x25519::public_key(&[9; 32]).to_vec()),
    };
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x42; 32]);
    body.push(32);
    body.extend_from_slice(&SESSION_ID);
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut exts = ext(EXT_SUPPORTED_VERSIONS, &[3, 4]);
    let mut share = g.to_be_bytes().to_vec();
    share.extend(block16(&public));
    exts.extend(ext(EXT_KEY_SHARE, &share));
    body.extend(block16(&exts));
    let sh = handshake_message(HS_SERVER_HELLO, &body);
    let mut out = plain_record(RT_HANDSHAKE, &hrr);
    out.extend(plain_record(RT_CHANGE_CIPHER_SPEC, &[1]));
    out.extend(plain_record(RT_HANDSHAKE, &sh));
    out
}

/// Raw bytes from the wire into a fresh client: the record layer and the plaintext ServerHello.
/// `data[0]` chooses the piece size.
pub fn server_bytes(data: &[u8]) {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let cfg = ClientConfig::new(TrustStore::empty()).danger_disable_verification();
    let mut c = ClientConnection::start("example.test", &cfg, Zeroizing::new(PRIVATE), &RANDOM, &SESSION_ID);
    let out = c.output().len();
    c.consume_output(out);
    drive(&mut c, bytes, pick_piece(sel));
}

/// A server flight: `data[2..]` is the plaintext of the handshake records the server sends after
/// a correct ServerHello (it is sealed with the keys the client derived, so it passes the record
/// MAC and reaches the message parsers). `data[0]` chooses the cipher suite and whether the
/// certificate chain is verified (against a trust store that fits `example_chain`), `data[1]` how
/// the flight is cut into records (low bits) and whether the server first sends a
/// HelloRetryRequest (bits 4 and 5). The handshake must never complete.
pub fn server_flight(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let suite = Suite::ALL[(data[0] % 3) as usize];
    let verify = data[0] & 0x08 != 0;
    let piece = pick_piece(data[1]).min(MAX_PLAINTEXT);
    let flight = data[2..].to_vec();
    let cfg = if verify {
        let mut cfg = ClientConfig::new(example_trust());
        cfg.time_override = Some(NOW);
        cfg
    } else {
        ClientConfig::new(TrustStore::empty()).danger_disable_verification()
    };
    // data[1] >> 4: 0 a plain handshake, 1 to 3 a HelloRetryRequest first (see `RetryServer`)
    let retry = (data[1] >> 4) & 3;
    if retry != 0 {
        let io = RetryServer::new(suite, retry, flight, piece);
        if TlsStream::connect(io, "example.test", &cfg).is_ok() {
            panic!("a fuzzed server flight completed a handshake after a HelloRetryRequest");
        }
        return;
    }
    let respond = move |h: Hello| {
        let s = Session::new(h, suite);
        let (mut out, sh) = s.hello_records(&ShOpts::default());
        let mut cipher = s.flight_cipher(&sh);
        for chunk in flight.chunks(piece) {
            cipher.encrypt_into(RT_HANDSHAKE, chunk, &mut out);
        }
        out
    };
    let (io, _) = FakeServer::new(respond);
    if TlsStream::connect(io, "example.test", &cfg).is_ok() {
        panic!("a fuzzed server flight completed a handshake");
    }
}

/// Records sent to an established connection: `data[0]` chooses the suite (and, with bit 3 set, a
/// tiny rekey interval, so our own KeyUpdates and writes are exercised), then each record is
/// `[inner type][length][content]`. The records are sealed with the peer's keys, which follow
/// every KeyUpdate the way a real peer's would. Inner type 0xff makes the client write the content
/// as application data instead.
pub fn peer_records(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else { return };
    let suite = Suite::ALL[(sel % 3) as usize];
    let n = suite.hash().output_len();
    let (read_secret, write_secret) = (vec![2u8; n], vec![1u8; n]);
    let mut c = ClientConnection::established(suite, &read_secret, &write_secret);
    if sel & 0x08 != 0 {
        c.set_rekey_after(2 + (sel >> 4) as u64);
    }
    let mut peer = RecordCipher::new(suite, &read_secret);
    while rest.len() >= 2 {
        let (ty, len) = (rest[0], rest[1] as usize);
        rest = &rest[2..];
        let take = len.min(rest.len());
        let content = &rest[..take];
        rest = &rest[take..];
        if ty == 0xff {
            let _ = c.write_plaintext(content);
            let out = c.output().len();
            c.consume_output(out);
            continue;
        }
        let mut record = Vec::new();
        peer.encrypt_into(ty, content, &mut record);
        if ty == RT_HANDSHAKE && content.len() == 5 && content[0] == HS_KEY_UPDATE && content[1..4] == [0, 0, 1] && content[4] <= 1 {
            peer = peer.next_generation();
        }
        if !drive(&mut c, &record, usize::MAX) {
            return;
        }
    }
}
