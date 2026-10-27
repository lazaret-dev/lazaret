# lazaret-archive

Bounded, in-memory archive extraction in native Rust. The crate uses no external
crates, performs no filesystem or network I/O, and forbids `unsafe` code.
Lazaret's existing ZIP implementation is separate and unchanged.

## Support matrix

| Input | Behavior |
| --- | --- |
| TAR | Regular files and directories; ustar, PAX `path`/`size` (plus times, ownership, comments, `hdrcharset` and extended attributes, which are ignored), PAX global headers holding only `comment`/`mtime` (`git archive`), and GNU long names |
| GZIP | One in-memory file, with optional `FNAME` recovery |
| TAR.GZ / TGZ | Inflate with the workspace decoder, then parse as TAR |
| RAR4 / RAR5 | **Store-method members only**, with header and member CRC checks; RAR 7's locator and metadata records, comments and recovery records are skipped |
| 7-Zip | Copy, DEFLATE, LZMA1, LZMA2; encoded headers, multiple files per folder, empty entries, and CRC checks |
| Bzip2 | One in-memory file; block and combined CRC checks, multi-block and concatenated streams (pbzip2), unused selectors (lbzip2) |
| XZ | One in-memory file; single-filter LZMA2 blocks, index verification, None/CRC32/CRC64 checks |
| LZMA-alone | One in-memory file; known-size and end-marker streams |

These single-file formats can be used directly for compressed pickle payloads;
the extracted entry is named `data`. The library decompresses but never executes
or deserializes pickle content. XZ filter chains and SHA-256 integrity checks are
unsupported. Concatenated XZ streams are not currently accepted.

Compressed RAR is not store-method RAR and is **not supported yet**. Encrypted,
solid, split/multi-volume, service-header, link, device, FIFO, sparse, and other
special entries fail closed. Encrypted 7-Zip, coder chains (including BCJ filters),
external metadata, additional streams, and anti entries are unsupported.
No partial archive is returned after an error. Non-UTF-8 or encoded RAR names and
unsupported TAR metadata are also refused.

PAX metadata is limited to `path`, `size`, timestamps, numeric/user/group
identity fields, comments, `hdrcharset` and `SCHILY.xattr.*`/`LIBARCHIVE.xattr.*`
extended attributes. Sparse maps, link paths and unknown extensions are refused.
A TAR ends at its last member or at a zero block followed only by zeros; empty
TAR/TGZ and a `./` root directory are supported. 7-Zip Unix file types (read from
the attribute's high bits whether or not the Unix-extension bit is set) and Windows
reparse attributes are checked before returning any entries.

## Failing closed against real extractors

A scanner that reads an archive differently from the extractor that installs it can
be shown one file while another is written. This crate returns an archive only in a
shape that the extractors people use read alike: Python's `tarfile` (pip), node-tar
(npm), GNU tar and bsdtar for TAR; 7-Zip and bsdtar for 7-Zip; unrar and 7-Zip for
RAR; bzip2/xz and Python for the compressed streams. Where they disagree the error is
`Error::Ambiguous`, which a caller should report as a finding in its own right. For
TAR that covers, among others: a number that starts with NUL, a file whose name ends
in `/`, a ustar prefix outside a POSIX ustar header, two pax headers or long names
(or one of each) for a member, bytes in metadata padding, a signed header checksum,
a link name on a header that is not a link, pax records node-tar parses differently
(leading-zero lengths, line breaks, all-digit paths, non-ASCII paths it may decode in
pieces), metadata over 1 MiB, and data after a single zero block. Callers that know which format bytes
should be (from a file name, as the extractor that opens them does) should use
`extract_as`; `detect` refuses bytes a TAR reader would find members in after
skipping a bad first block.

Where only the *path* an entry lands at depends on the extractor or file system, every
entry is returned and the archive says so: `Archive::collisions` groups entries some
extractor or file system writes to one path (the same name; names that differ only in
case, Unicode normalization, default-ignorable characters or `\` against `/`, as
`path_key` folds them; or a file where another entry needs a directory), and
`Entry::windows_name` gives the path a Windows extractor writes when `\` (kept in
`name`, as Linux extractors keep it) splits it there. `Archive::is_path_ambiguous`
tells a caller to report it; any name in a group may end up holding any of the
group's bytes.

## API

```rust
use lazaret_archive::{extract_with_limits, EntryKind, Limits};

let bytes = std::fs::read("input.rar")?;
let limits = Limits::new(32 * 1024 * 1024, 128 * 1024 * 1024);
let archive = extract_with_limits(&bytes, limits)?;

for entry in archive.entries {
    if entry.kind == EntryKind::File {
        println!("{}: {} bytes", entry.name, entry.data.len());
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example's file read belongs to the caller; the library itself only accepts
byte slices. `detect` identifies known containers without extracting them.
`extract` applies `Limits::default`.

Default limits are 250,000 entries, 128 MiB per member, 500 MiB total output,
4,096 bytes per name, and 1 MiB per metadata item. Structural sizes and offsets
are checked before slicing or copying.
Names are canonicalized without touching the host filesystem; absolute paths,
parent traversal, drive/alternate-stream syntax, control characters, reserved
Windows device names and ambiguous trailing dots/spaces are refused, in the name and
in its Windows reading. Colliding names are returned and grouped (above); `path_key`
over-approximates the file systems' folding on purpose (NTFS, APFS, HFS+, ext4
casefold), from Unicode 15.1 data in `src/fold_table.rs`
(`tests/fixtures/generate_fold_table.py` writes it and checks it with `--check`).

Output limits are not a process memory or CPU budget. Decoder buffers, metadata,
entry copies, and the caller's input also occupy memory; callers handling
untrusted uploads should cap input size and concurrent work. Each call handles
one container; any recursive scan must impose its own cumulative depth and byte
limits. Unsupported or corrupt input must remain an error in the caller's scan
result. No archive member or pickle payload is executed by this crate.

## Fixtures and tests

`tests/fixtures/generate.py`, `generate_7z.py`, and
`generate_compressed_pickle.py`, and `generate_review.py` regenerate fixtures using only Python's
standard library. `tests/review_fixes.rs` builds its TAR and gzip cases in the test,
as the independent review's generator did; `tests/fixtures/review-fixes` holds the
review's other inputs, from its generators: hand-built 7-Zip and RAR headers, and
archives written by 7-Zip 23.01, RAR 7.00, lbzip2 2.5, pbzip2 and Python's bz2
from inert text (`real_store5*.rar`, `b_*_lbzip2.bz2`, `b_*_pbzip2.bz2`).
Valid handwritten RAR and 7-Zip fixtures have been checked
independently with `bsdtar`; they do not depend on the Rust parser for validation.
`real-writer.7z` was produced directly by the system `bsdtar` 7-Zip writer. LZMA
coverage includes encoded headers, multiple files per folder, and state/history
continuing across compressed chunks. The Bzip2/XZ/LZMA-alone fixtures contain a
real protocol-5 pickle and are independently decoded and deserialized by Python.

Run the Rust tests from the `rust` workspace:

```text
cargo test --offline --locked -p lazaret-archive
cargo test --release --offline --locked -p lazaret-archive
cargo check --offline --locked --target wasm32-unknown-unknown -p lazaret-archive
```
