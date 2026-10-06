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

/// The Go checksum database's answer for one `module@version`, checked as the go command checks it (NET-1): the tree
/// head's signature by the database's key, the head against one saved from before (if given), and the record's place
/// in the log through tiles that are each authenticated against the signed root (`sumdb::Check`). In two steps, as
/// the caller does the fetching: `tiles_needed` names the tiles, `verify` takes them.
pub mod gosum {
    use super::note::Verifier;
    use super::sumdb::Check;
    use super::tlog::{Tile, TileSet};

    /// The most tiles one check reads (a lookup in a tree of 2^62 records needs eight levels, twice).
    pub const MAX_TILES: usize = 64;

    /// A tile to fetch: its path, and the full tile's, which the database serves when a partial one is gone; and the
    /// bytes each has.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NeededTile {
        pub path: String,
        pub full_path: String,
        pub len: u64,
        pub full_len: u64,
    }

    /// What a check vouches for: the record's lines that start with `module version ` (the hash of the module's
    /// files), the whole record (its go.mod's line too: `module version/go.mod h1:…`), the record's number, and the
    /// newest tree head seen (its size and its signed note, to keep).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Verified {
        pub lines: Vec<String>,
        pub record: String,
        pub id: u64,
        pub size: u64,
        pub latest_note: Vec<u8>,
    }

    fn check_of(key: &str, head: Option<&[u8]>, module: &str, version: &str, lookup: &[u8]) -> Result<Check, String> {
        let verifier = Verifier::from_key(key).map_err(|e| format!("the database's key: {e}"))?;
        let mut check = Check::new(verifier);
        if let Some(head) = head {
            check.add_head(head).map_err(|e| format!("the tree head kept from before: {e}"))?;
        }
        check.add_lookup(module, version, lookup).map_err(|e| format!("the lookup: {e}"))?;
        Ok(check)
    }

    /// The tiles `verify` will read for this lookup (each once).
    pub fn tiles_needed(key: &str, head: Option<&[u8]>, module: &str, version: &str, lookup: &[u8])
                        -> Result<Vec<NeededTile>, String> {
        let tiles = check_of(key, head, module, version, lookup)?.tiles_needed().map_err(|e| format!("the tiles: {e}"))?;
        if tiles.len() > MAX_TILES {
            return Err(format!("the lookup needs {} tiles, more than {MAX_TILES}", tiles.len()));
        }
        Ok(tiles.iter().map(|t| NeededTile { path: t.path(), full_path: t.full().path(), len: t.data_len(),
                                             full_len: t.full().data_len() }).collect())
    }

    /// The lookup checked with these tiles (each under the path it was fetched by: a partial tile's, or the full
    /// one's that stood in for it). Nothing is vouched for unless every check passes.
    pub fn verify(key: &str, head: Option<&[u8]>, module: &str, version: &str, lookup: &[u8], tiles: &[(String, Vec<u8>)])
                  -> Result<Verified, String> {
        let check = check_of(key, head, module, version, lookup)?;
        if tiles.len() > MAX_TILES {
            return Err(format!("{} tiles, more than {MAX_TILES}", tiles.len()));
        }
        let mut set = TileSet::new();
        for (path, data) in tiles {
            let tile = Tile::parse_path(path).map_err(|e| format!("tile {path}: {e}"))?;
            let tile = if data.len() as u64 == tile.data_len() {
                tile
            } else if data.len() as u64 == tile.full().data_len() {
                tile.full()
            } else {
                return Err(format!("tile {path}: {} bytes, where it has {}", data.len(), tile.data_len()));
            };
            set.insert(tile, data.clone()).map_err(|e| format!("tile {path}: {e}"))?;
        }
        let outcome = check.finish(&set).map_err(|e| format!("{e}"))?;
        let record = outcome.records.into_iter().next().ok_or("no record was checked")?;
        Ok(Verified { lines: record.lines, record: record.text, id: record.id, size: outcome.latest.size,
                      latest_note: outcome.latest_note })
    }
}

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
    fn gosum_names_the_tiles_and_vouches_for_the_lines() {
        use super::gosum;
        let needed = gosum::tiles_needed(sumdb::KEY, Some(LATEST), "golang.org/x/mod", "v0.17.0", LOOKUP).unwrap();
        let mut paths: Vec<&str> = needed.iter().map(|t| t.path.as_str()).collect();
        paths.sort();
        let mut want: Vec<&str> = TILES.iter().map(|(p, _)| *p).collect();
        want.sort();
        assert_eq!(paths, want);
        let tiles: Vec<(String, Vec<u8>)> = TILES.iter().map(|(p, d)| (p.to_string(), d.to_vec())).collect();
        let v = gosum::verify(sumdb::KEY, Some(LATEST), "golang.org/x/mod", "v0.17.0", LOOKUP, &tiles).unwrap();
        assert_eq!(v.lines, vec!["golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=".to_string()]);
        assert!(v.record.contains("golang.org/x/mod v0.17.0/go.mod h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c=\n"));
        assert_eq!((v.id, v.size), (24955599, 66746981));
        // without the older head, the lookup alone (its own signed head) is enough
        let alone = gosum::tiles_needed(sumdb::KEY, None, "golang.org/x/mod", "v0.17.0", LOOKUP).unwrap();
        let need: Vec<(String, Vec<u8>)> = tiles.iter().filter(|(p, _)| alone.iter().any(|t| &t.path == p)).cloned().collect();
        assert!(gosum::verify(sumdb::KEY, None, "golang.org/x/mod", "v0.17.0", LOOKUP, &need).is_ok());
    }

    #[test]
    fn gosum_refuses_another_key_a_changed_tile_and_a_missing_one() {
        use super::gosum;
        let tiles: Vec<(String, Vec<u8>)> = TILES.iter().map(|(p, d)| (p.to_string(), d.to_vec())).collect();
        let other = "sum.golang.org+033de0ae+AaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA";
        assert!(gosum::verify(other, None, "golang.org/x/mod", "v0.17.0", LOOKUP, &tiles).is_err(), "another key");
        let mut changed = tiles.clone();
        changed[0].1[0] ^= 1;
        assert!(gosum::verify(sumdb::KEY, Some(LATEST), "golang.org/x/mod", "v0.17.0", LOOKUP, &changed).is_err());
        assert!(gosum::verify(sumdb::KEY, Some(LATEST), "golang.org/x/mod", "v0.17.0", LOOKUP, &tiles[1..]).is_err());
        let mut cut = tiles.clone();
        cut[0].1.pop();
        assert!(gosum::verify(sumdb::KEY, Some(LATEST), "golang.org/x/mod", "v0.17.0", LOOKUP, &cut).is_err(), "a short tile");
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
