//! What Lazaret takes from tiny_https's pure part (NET-1): verification over bytes, with the time and the trust
//! anchors given by the caller. No I/O, no threads, no clock, no `unsafe`, and it builds for WebAssembly, so the
//! engine may use it where it reads a release (the Go checksum database's records, npm's and PyPI's
//! attestations, signed archives).
//!
//! The modules are tiny_https's own (`rust/crates/tiny_https`, taken as it was handed over by
//! `scripts/sync_tiny_https.py`); this crate names the ones Lazaret uses, so that the engine depends on this
//! crate and never on the network part (`scripts/check_rust_deps.py` checks both).
#![forbid(unsafe_code)]

pub use tiny_https::{asn1, ber, cms, crypto, json, note, pem, revocation, sigstore, sumdb, tlog, trust_root, util,
                     verify_error, x509};

#[cfg(test)]
mod tests {
    use super::sumdb::{self, Check};
    use super::tlog::{Tile, TileSet};

    // tiny_https's capture of the real `sum.golang.org` (its tests/data/sumdb/README.txt): the lookup of
    // golang.org/x/mod@v0.17.0 and the tiles a Go client reads for it.
    const LATEST: &[u8] = include_bytes!("../../tiny_https/tests/data/sumdb/latest.txt");
    const LOOKUP: &[u8] = include_bytes!("../../tiny_https/tests/data/sumdb/lookup.txt");
    const TILES: [(&str, &[u8]); 7] = [
        ("tile/8/0/x097/482", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/0/x097/482")),
        ("tile/8/0/x260/730.p/101", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/0/x260/730.p/101")),
        ("tile/8/1/380", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/1/380")),
        ("tile/8/1/x001/018.p/122", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/1/x001/018.p/122")),
        ("tile/8/2/001", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/2/001")),
        ("tile/8/2/003.p/250", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/2/003.p/250")),
        ("tile/8/3/000.p/3", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/3/000.p/3")),
    ];

    fn tiles() -> TileSet {
        let mut set = TileSet::new();
        for (path, data) in TILES {
            set.insert(Tile::parse_path(path).unwrap(), data.to_vec()).unwrap();
        }
        set
    }

    #[test]
    fn the_checksum_database_is_checked_through_this_crate() {
        let mut check = Check::new(sumdb::verifier());
        check.add_head(LATEST).unwrap();
        check.add_lookup("golang.org/x/mod", "v0.17.0", LOOKUP).unwrap();
        let outcome = check.finish(&tiles()).unwrap();
        assert_eq!(outcome.records[0].lines[0], "golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=");
    }

    #[test]
    fn a_changed_record_is_refused() {
        let text = String::from_utf8(LOOKUP.to_vec()).unwrap().replacen("h1:zY54", "h1:zY55", 1);
        let mut check = Check::new(sumdb::verifier());
        check.add_head(LATEST).unwrap();
        check.add_lookup("golang.org/x/mod", "v0.17.0", text.as_bytes()).unwrap();
        assert!(check.finish(&tiles()).is_err(), "a record that is not the one the log holds must not verify");
    }
}
