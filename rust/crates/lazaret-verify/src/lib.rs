//! What Lazaret takes from pratique's pure part (NET-1): verification over bytes, with the time and the trust
//! anchors given by the caller. No I/O, no threads, no clock, no `unsafe`, and it builds for WebAssembly, so the
//! engine may use it where it reads a release (the Go checksum database's records, npm's and PyPI's
//! attestations, signed archives).
//!
//! The modules are pratique's own (`rust/crates/pratique`, taken as it is upstream by
//! `scripts/sync_pratique.py`); this crate names the ones Lazaret uses, so that the engine depends on this
//! crate and never on the network part (`scripts/check_rust_deps.py` checks both).
#![forbid(unsafe_code)]

pub use pratique::{asn1, ber, cms, crypto, json, note, pem, revocation, sigstore, sumdb, tlog, trust_root, util,
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

/// npm's and PyPI's attestations of one file, checked (NET-1's provenance findings): each is verified by
/// pratique's `sigstore` against Sigstore's trusted root (and npm's key ring, for npm's own publish attestation),
/// with the file's digest (npm: the tarball's SHA-512; PyPI: the file's SHA-256), and comes back as what it
/// proves or as one of two kinds of failure: **invalid**, when the attestation is not about this file (no subject
/// has its digest) or its signature is not by its signer's key, which no age of the trust explains; and
/// **unchecked**, for every other reason (a log, authority or key the trust does not know, a form not read here,
/// no time established), which says nothing against the file.
pub mod provenance {
    use super::sigstore::{ArtifactDigest, Bundle, BundleFormat, DigestAlgorithm, Error, Signer, Trust, Verified};
    use super::trust_root::{KeyRing, TrustedRoot};

    /// Which registry's document it is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Registry {
        /// `/-/npm/v1/attestations/<name>@<version>`: the file is the tarball, its SHA-512.
        Npm,
        /// `/integrity/<project>/<version>/<file>/provenance` (PEP 740): the file's SHA-256.
        PyPI,
    }

    /// Who signed, as far as it was verified.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Who {
        /// A Fulcio certificate: the CI identity it certifies (each as the certificate has it).
        Certificate {
            issuer: Option<String>,
            /// the source repository's URI, and the IDs that stay when it is renamed or moved
            repository: Option<String>,
            repository_id: Option<String>,
            owner: Option<String>,
            owner_id: Option<String>,
            /// the workflow (the build configuration's URI), the Git ref and the commit it ran at
            workflow: Option<String>,
            git_ref: Option<String>,
            commit: Option<String>,
            /// `github-hosted` or `self-hosted`, and what started the run
            runner: Option<String>,
            trigger: Option<String>,
            /// the certificate's subject alternative names (URIs and e-mail addresses)
            names: Vec<String>,
        },
        /// A key of the ring (npm's own, for its publish attestation).
        Key { id: String },
    }

    /// One attestation's outcome.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Outcome {
        Verified { who: Who, time: i64, format: &'static str },
        Invalid(String),
        Unchecked(String),
    }

    /// One attestation: its predicate type (the signed one when it verified, else the one claimed) and outcome.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Checked {
        pub predicate_type: String,
        pub outcome: Outcome,
    }

    /// The most bytes of a document read (a real one is tens of kilobytes).
    pub const MAX_DOCUMENT: usize = 4 << 20;

    fn format_name(f: BundleFormat) -> &'static str {
        match f {
            BundleFormat::V0_1 => "bundle 0.1",
            BundleFormat::V0_2 => "bundle 0.2",
            BundleFormat::V0_3 => "bundle 0.3",
            BundleFormat::Pep740 => "PEP 740",
        }
    }

    fn outcome(result: Result<Verified, Error>) -> (Option<String>, Outcome) {
        match result {
            Ok(v) => {
                let who = match &v.signer {
                    Signer::Certificate(id) => Who::Certificate {
                        issuer: id.issuer.clone(),
                        repository: id.repository(),
                        repository_id: id.source_repository_identifier.clone(),
                        owner: id.source_repository_owner_uri.clone(),
                        owner_id: id.source_repository_owner_identifier.clone(),
                        workflow: id.build_config_uri.clone().or_else(|| id.uris.first().cloned()),
                        git_ref: id.git_ref().map(str::to_string),
                        commit: id.source_repository_digest.clone().or_else(|| id.github_workflow_sha.clone()),
                        runner: id.runner_environment.clone(),
                        trigger: id.build_trigger.clone().or_else(|| id.github_workflow_trigger.clone()),
                        names: id.uris.iter().chain(&id.emails).cloned().collect(),
                    },
                    Signer::Key { id, .. } => Who::Key { id: id.clone() },
                };
                (Some(v.statement.predicate_type.clone()),
                 Outcome::Verified { who, time: v.verified_time, format: format_name(v.format) })
            }
            Err(e @ (Error::SubjectMismatch | Error::Signature)) => (None, Outcome::Invalid(e.to_string())),
            Err(e) => (None, Outcome::Unchecked(e.to_string())),
        }
    }

    /// The trust: Sigstore's `trusted_root.json`, and npm's key list (`/-/npm/v1/keys`) for npm's publish
    /// attestation.
    pub fn trust(root: &[u8], npm_keys: Option<&[u8]>) -> Result<(TrustedRoot, KeyRing), String> {
        let root = TrustedRoot::parse(root).map_err(|e| format!("Sigstore's trusted root: {e}"))?;
        let ring = match npm_keys {
            Some(k) => KeyRing::from_npm_keys(k).map_err(|e| format!("npm's keys: {e}"))?,
            None => KeyRing::new(),
        };
        Ok((root, ring))
    }

    /// Every attestation of `document` checked against the file's `digest` (raw bytes: SHA-512 for npm, SHA-256 for
    /// PyPI). Err when the document is not a registry's attestations (nothing in it can be checked) or the digest
    /// is not one.
    pub fn check(registry: Registry, document: &[u8], digest: &[u8], root: &TrustedRoot, ring: &KeyRing)
                 -> Result<Vec<Checked>, String> {
        if document.len() > MAX_DOCUMENT {
            return Err(format!("the document is over {MAX_DOCUMENT} bytes"));
        }
        let trust = Trust::new(root).with_keys(ring);
        let algorithm = match registry {
            Registry::Npm => DigestAlgorithm::Sha512,
            Registry::PyPI => DigestAlgorithm::Sha256,
        };
        let digest = ArtifactDigest::new(algorithm, digest).map_err(|e| format!("the file's digest: {e}"))?;
        let mut out = Vec::new();
        match registry {
            Registry::Npm => {
                for a in Bundle::parse_npm_attestations(document).map_err(|e| format!("npm's attestations: {e}"))? {
                    let (signed, o) = outcome(a.verify(&trust, &digest));
                    out.push(Checked { predicate_type: signed.unwrap_or(a.claimed_predicate_type), outcome: o });
                }
            }
            Registry::PyPI => {
                for a in Bundle::parse_pep740(document).map_err(|e| format!("PyPI's provenance: {e}"))? {
                    let (signed, o) = outcome(a.verify(&trust, &digest));
                    out.push(Checked { predicate_type: signed.unwrap_or_default(), outcome: o });
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::sumdb::{self, Check};
    use super::tlog::{Tile, TileSet};

    // pratique's capture of the real `sum.golang.org` (its tests/data/sumdb/README.txt): the lookup of
    // golang.org/x/mod@v0.17.0 and the tiles a Go client reads for it.
    const LATEST: &[u8] = include_bytes!("../../pratique/tests/data/sumdb/latest.txt");
    const LOOKUP: &[u8] = include_bytes!("../../pratique/tests/data/sumdb/lookup.txt");
    const TILES: [(&str, &[u8]); 7] = [
        ("tile/8/0/x097/482", include_bytes!("../../pratique/tests/data/sumdb/tile/8/0/x097/482")),
        ("tile/8/0/x260/730.p/101", include_bytes!("../../pratique/tests/data/sumdb/tile/8/0/x260/730.p/101")),
        ("tile/8/1/380", include_bytes!("../../pratique/tests/data/sumdb/tile/8/1/380")),
        ("tile/8/1/x001/018.p/122", include_bytes!("../../pratique/tests/data/sumdb/tile/8/1/x001/018.p/122")),
        ("tile/8/2/001", include_bytes!("../../pratique/tests/data/sumdb/tile/8/2/001")),
        ("tile/8/2/003.p/250", include_bytes!("../../pratique/tests/data/sumdb/tile/8/2/003.p/250")),
        ("tile/8/3/000.p/3", include_bytes!("../../pratique/tests/data/sumdb/tile/8/3/000.p/3")),
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

    // pratique's real Sigstore data (its tests/data/sigstore/README.txt): Sigstore's trusted root, npm's keys, the
    // attestations of the npm package sigstore 4.0.0 with its tarball, and PyPI's provenance of a wheel with the wheel
    const ROOT: &[u8] = include_bytes!("../../pratique/tests/data/sigstore/trusted_root.json");
    const NPM_KEYS: &[u8] = include_bytes!("../../pratique/tests/data/sigstore/npm-registry-keys.json");
    const NPM_ATTESTATIONS: &[u8] = include_bytes!("../../pratique/tests/data/sigstore/sigstore-4.0.0.attestations.json");
    const NPM_TARBALL: &[u8] = include_bytes!("../../pratique/tests/data/sigstore/sigstore-4.0.0.tgz");
    const PYPI_PROVENANCE: &[u8] =
        include_bytes!("../../pratique/tests/data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl.provenance.json");
    const WHEEL: &[u8] = include_bytes!("../../pratique/tests/data/sigstore/pypi_attestations-0.0.30-py3-none-any.whl");

    fn digest(algorithm: super::sigstore::DigestAlgorithm, data: &[u8]) -> Vec<u8> {
        super::sigstore::ArtifactDigest::of(algorithm, data).bytes().to_vec()
    }

    #[test]
    fn provenance_of_a_real_npm_release() {
        use super::provenance::{self, Outcome, Registry, Who};
        use super::sigstore::DigestAlgorithm;
        let (root, ring) = provenance::trust(ROOT, Some(NPM_KEYS)).unwrap();
        let sha512 = digest(DigestAlgorithm::Sha512, NPM_TARBALL);
        let checked = provenance::check(Registry::Npm, NPM_ATTESTATIONS, &sha512, &root, &ring).unwrap();
        assert_eq!(checked.len(), 2);
        assert_eq!(checked[0].predicate_type, "https://github.com/npm/attestation/tree/main/specs/publish/v0.1");
        assert!(matches!(&checked[0].outcome, Outcome::Verified { who: Who::Key { id }, .. }
                         if id == "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"), "{:?}", checked[0]);
        assert_eq!(checked[1].predicate_type, "https://slsa.dev/provenance/v1");
        match &checked[1].outcome {
            Outcome::Verified { who: Who::Certificate { issuer, repository, repository_id, owner_id, workflow, git_ref, .. }, time, format } => {
                assert_eq!(issuer.as_deref(), Some("https://token.actions.githubusercontent.com"));
                assert_eq!(repository.as_deref(), Some("https://github.com/sigstore/sigstore-js"));
                assert!(repository_id.is_some() && owner_id.is_some());
                assert!(workflow.as_deref().unwrap().starts_with("https://github.com/sigstore/sigstore-js/.github/workflows/"), "{workflow:?}");
                assert_eq!(git_ref.as_deref(), Some("refs/heads/main"));
                assert_eq!((*time, *format), (1_753_831_006, "bundle 0.3"));
            }
            other => panic!("{other:?}"),
        }
        // another file: neither attestation is about it
        let other = digest(DigestAlgorithm::Sha512, b"another tarball");
        for c in provenance::check(Registry::Npm, NPM_ATTESTATIONS, &other, &root, &ring).unwrap() {
            assert!(matches!(c.outcome, Outcome::Invalid(_)), "{c:?}");
        }
        // without npm's keys the registry's own attestation cannot be checked, which says nothing against the file
        let (root, empty) = provenance::trust(ROOT, None).unwrap();
        let checked = provenance::check(Registry::Npm, NPM_ATTESTATIONS, &sha512, &root, &empty).unwrap();
        assert!(matches!(checked[0].outcome, Outcome::Unchecked(_)), "{:?}", checked[0]);
        assert!(matches!(checked[1].outcome, Outcome::Verified { .. }));
        // a document that is not attestations, and a digest that is not one
        assert!(provenance::check(Registry::Npm, b"{\"attestations\": 5}", &sha512, &root, &ring).is_err());
        assert!(provenance::check(Registry::Npm, NPM_ATTESTATIONS, &sha512[..32], &root, &ring).is_err());
    }

    #[test]
    fn provenance_of_a_real_wheel_and_a_trust_that_does_not_know_its_log() {
        use super::provenance::{self, Outcome, Registry, Who};
        use super::sigstore::DigestAlgorithm;
        let (root, ring) = provenance::trust(ROOT, None).unwrap();
        let sha256 = digest(DigestAlgorithm::Sha256, WHEEL);
        let checked = provenance::check(Registry::PyPI, PYPI_PROVENANCE, &sha256, &root, &ring).unwrap();
        assert_eq!(checked.len(), 1);
        assert_eq!(checked[0].predicate_type, "https://docs.pypi.org/attestations/publish/v1");
        assert!(matches!(&checked[0].outcome, Outcome::Verified { who: Who::Certificate { repository, workflow, .. }, format: "PEP 740", .. }
                         if repository.as_deref() == Some("https://github.com/pypi/pypi-attestations")
                         && workflow.as_deref().is_some_and(|w| w.contains("/.github/workflows/release.yml"))), "{:?}", checked[0]);
        let other = digest(DigestAlgorithm::Sha256, b"another wheel");
        let checked = provenance::check(Registry::PyPI, PYPI_PROVENANCE, &other, &root, &ring).unwrap();
        assert!(matches!(checked[0].outcome, Outcome::Invalid(_)));
        // a trusted root without its transparency logs: the attestation cannot be checked; that is not "invalid"
        let text = String::from_utf8(ROOT.to_vec()).unwrap();
        let start = text.find("\"tlogs\"").unwrap();
        let open = start + text[start..].find('[').unwrap();
        let mut depth = 0;
        let mut close = open;
        for (i, ch) in text[open..].char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let no_logs = format!("{}[]{}", &text[..open], &text[close + 1..]);
        match provenance::trust(no_logs.as_bytes(), None) {
            Ok((root, ring)) => {
                let checked = provenance::check(Registry::PyPI, PYPI_PROVENANCE, &sha256, &root, &ring).unwrap();
                assert!(matches!(checked[0].outcome, Outcome::Unchecked(_)), "{:?}", checked[0]);
            }
            Err(e) => assert!(e.contains("trusted root"), "{e}"),           // (a root may be required to have a log)
        }
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
