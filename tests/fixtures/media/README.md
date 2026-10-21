# Media fixtures (FP-OPAQUE-MEDIA)

Small sound, video, image and font files written by the real encoders, for the walker of
`rust/crates/lazaret-engine/src/media/` and the tests that hold the scan's routes to it. Made by
`scripts/make_media_fixtures.py` (ffmpeg, Pillow and fontTools). What a codec compresses (`noise.*`) is seeded
noise, so that each file is near-random, as SC-OPAQUE-BLOB sees compressed media; the formats that store their
samples raw (`signal.*`: BMP, PPM, PGM, PBM, TGA, WAV, AIFF) hold ramps and a tone with a little noise instead,
as varied but following one another as a real picture's or sound's samples do (the walk requires that of a raw
format). The fonts are glyphs drawn by the script, and `gradient.imt` is Pillow's IM Tools test image's shape (a
header, then a grey gradient). Nothing here is anyone's file, and nothing here runs. `MANIFEST` holds each
file's SHA-256 (`--check` compares).
