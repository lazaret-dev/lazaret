#!/usr/bin/env python3
"""Write tests/fixtures/media: small sound, video, image and font files made by the real encoders (FP-OPAQUE-MEDIA).

    python3 scripts/make_media_fixtures.py [--out DIR]

The walker of media.rs (rust/crates/lazaret-engine/src/media/) is held to files the encoders people use wrote, not
only to the structures the tests build: ffmpeg's muxers (MP3 with and without its ID3v2 tag and Xing frame, AAC in
ADTS, MPEG-4 audio and video, QuickTime, 3GPP, Matroska, WebM, Ogg Opus, FLAC, WAV, AIFF, AVI, an MPEG transport
stream; an MP3 with an ID3v1 tag), Pillow's (PNG, APNG, JPEG baseline and progressive, GIF, animated GIF, BMP, ICO, TIFF raw, LZW and JPEG
compressed, WebP lossy and lossless, JPEG 2000, AVIF, binary PPM, PGM and PBM, TGA raw and run-length; an Apple icon
of its PNGs, laid out as macOS's iconutil writes one) and fontTools' (a
TrueType and a CFF OpenType font built here, a collection of the two, WOFF, WOFF2). The pictures and sounds the
codecs compress are noise from a seeded generator, so that the files are near-random, as the scanner's
SC-OPAQUE-BLOB sees them; the formats that store their samples raw (BMP, Netpbm, TGA, WAV and AIFF: `signal.*`) hold
a signal instead, ramps and a tone with a little noise, whose bytes are as varied but follow one another as a real
picture's or sound's do (the walk requires it of a raw format's samples); the fonts are two glyphs drawn here.
Nothing is taken from anyone's files, and nothing here runs.

Needs ffmpeg (with libmp3lame, libopus, libx264, libvpx), Pillow with WebP, JPEG 2000 and AVIF, and fontTools with
brotli (WOFF2). The tests use the files written; they do not need this script or its tools. Each file's sha256 is
in the directory's MANIFEST, which --check compares with what is there.
"""
import argparse
import hashlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import wave

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "tests", "fixtures", "media")
SEED = 20261021


def noise_image(size, mode="RGB", seed=SEED):
    from PIL import Image
    rnd = random.Random(seed)
    bands = {"RGB": 3, "RGBA": 4, "L": 1, "P": 1}[mode]
    data = bytes(rnd.randrange(256) for _ in range(size[0] * size[1] * bands))
    if mode == "P":
        img = Image.frombytes("L", size, data).convert("P")
        return img
    return Image.frombytes(mode, size, data)


def signal_image(size, mode="RGB", seed=SEED):
    """Ramps of every level in each band, and a little noise: a picture's samples, each near its neighbour."""
    from PIL import Image
    rnd = random.Random(seed)
    bands = {"RGB": 3, "RGBA": 4, "L": 1}[mode]
    data = bytes((x * (5 + 2 * c) + y * (11 + c) + rnd.randrange(-2, 3)) % 256
                 for y in range(size[1]) for x in range(size[0]) for c in range(bands))
    return Image.frombytes(mode, size, data)


def pillow(out):
    from PIL import Image
    img = noise_image((48, 48))
    files = {}

    def save(name, image, **kw):
        buf = io.BytesIO()
        image.save(buf, **kw)
        files[name] = buf.getvalue()

    save("noise.png", img, format="PNG")
    frames = [noise_image((32, 32), seed=SEED + k) for k in range(3)]
    save("noise-anim.png", frames[0], format="PNG", save_all=True, append_images=frames[1:])
    save("noise.jpg", img, format="JPEG", quality=95)
    save("noise-progressive.jpg", img, format="JPEG", quality=95, progressive=True)
    save("noise.gif", noise_image((48, 48), "P"), format="GIF")
    save("noise-anim.gif", noise_image((32, 32), "P"), format="GIF", save_all=True,
         append_images=[noise_image((32, 32), "P", SEED + 1)])
    save("signal.bmp", signal_image((24, 24)), format="BMP")
    save("noise.ico", noise_image((32, 32), "RGBA"), format="ICO", sizes=[(16, 16), (32, 32)])
    save("noise-raw.tif", noise_image((24, 24)), format="TIFF")
    save("noise-lzw.tif", noise_image((32, 32)), format="TIFF", compression="tiff_lzw")
    save("noise-jpeg.tif", noise_image((32, 32)), format="TIFF", compression="jpeg")
    save("noise-lossy.webp", img, format="WEBP", quality=90)
    save("noise-lossless.webp", img, format="WEBP", lossless=True)
    save("noise.jp2", img, format="JPEG2000")
    save("noise.avif", img, format="AVIF", quality=90)
    save("signal.ppm", signal_image((24, 24)), format="PPM")
    save("signal.pgm", signal_image((40, 40), "L"), format="PPM")
    save("signal.pbm", signal_image((96, 96), "L").convert("1", dither=Image.Dither.NONE), format="PPM")
    save("signal.tga", signal_image((24, 24)), format="TGA")
    save("signal-rle.tga", signal_image((32, 32), "RGBA"), format="TGA", compression="tga_rle")
    # an Apple icon as macOS's iconutil writes one: a table of contents, then 16 and 32 pixel PNG elements (Pillow's
    # writer makes every size up to 1,024 pixels: megabytes of noise)
    elements = []
    for kind, px in ((b"icp4", 16), (b"icp5", 32)):
        buf = io.BytesIO()
        noise_image((px, px), "RGBA", SEED + px).save(buf, format="PNG")
        elements.append((kind, buf.getvalue()))
    toc = b"".join(kind + (8 + len(data)).to_bytes(4, "big") for kind, data in elements)
    body = [(b"TOC ", toc)] + elements
    data = b"".join(kind + (8 + len(d)).to_bytes(4, "big") + d for kind, d in body)
    files["noise.icns"] = b"icns" + (8 + len(data)).to_bytes(4, "big") + data
    for name, data in files.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)


def noise_wav(path, seconds=0.05, rate=22050, seed=SEED):
    rnd = random.Random(seed)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(rnd.randrange(256) for _ in range(int(seconds * rate) * 2)))


def signal_wav(path, seconds=0.1, rate=22050, seed=SEED):
    """A tone (220 Hz) and a little noise: a sound's samples, each near the one before."""
    import math
    rnd = random.Random(seed)
    frames = bytearray()
    for i in range(int(seconds * rate)):
        v = int(12000 * math.sin(2 * math.pi * 220 * i / rate)) + rnd.randrange(-64, 65)
        frames += max(-32768, min(32767, v)).to_bytes(2, "little", signed=True)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))


def flac_without_padding(data):
    """A FLAC file with its PADDING metadata blocks dropped, as `metaflac --remove --block-type=PADDING` does (ffmpeg's
    muxer leaves 8 KiB of zeros at the start, which a scan's sample would read)."""
    out, i, blocks = bytearray(data[:4]), 4, []
    while True:
        last, kind, n = data[i] & 0x80, data[i] & 0x7f, int.from_bytes(data[i + 1:i + 4], "big")
        blocks.append((kind, data[i + 4:i + 4 + n]))
        i += 4 + n
        if last:
            break
    kept = [(k, b) for k, b in blocks if k != 1]
    for j, (kind, body) in enumerate(kept):
        out += bytes([kind | (0x80 if j == len(kept) - 1 else 0)]) + len(body).to_bytes(3, "big") + body
    return bytes(out + data[i:])


def ffmpeg(out, tmp):
    src = os.path.join(tmp, "noise.wav")
    noise_wav(src, seconds=1.0)
    video = ["-f", "lavfi", "-i", "nullsrc=s=32x32:d=0.4:r=10,geq=random(1)*255:128:128"]
    run = lambda *a: subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *a], check=True)
    meta = ["-map_metadata", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact", "-flags:v", "+bitexact"]
    run("-i", src, *meta, "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "22050", "-id3v2_version", "3",
        "-metadata", "title=noise", os.path.join(out, "noise-id3.mp3"))
    run("-i", src, *meta, "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "22050", "-id3v2_version", "0",
        "-write_xing", "0", os.path.join(out, "noise-raw.mp3"))
    run("-i", src, *meta, "-c:a", "aac", "-b:a", "32k", "-ar", "22050", "-f", "adts", os.path.join(out, "noise.aac"))
    run("-i", src, *meta, "-c:a", "aac", "-b:a", "32k", "-ar", "22050", os.path.join(out, "noise.m4a"))
    run("-i", src, *meta, "-c:a", "libopus", "-b:a", "24k", os.path.join(out, "noise.opus"))
    run("-i", src, *meta, "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "22050", "-id3v2_version", "0",
        "-write_id3v1", "1", "-metadata", "title=noise", "-t", "0.3", os.path.join(out, "noise-id3v1.mp3"))
    run("-i", src, *meta, "-t", "0.2", "-c:a", "flac", "-ar", "22050", os.path.join(out, "noise.flac"))
    with open(os.path.join(out, "noise.flac"), "rb") as f:
        flac = f.read()
    with open(os.path.join(out, "noise-nopad.flac"), "wb") as f:
        f.write(flac_without_padding(flac))
    tone = os.path.join(tmp, "signal.wav")
    signal_wav(tone)
    run("-i", tone, *meta, "-c:a", "pcm_s16le", os.path.join(out, "signal.wav"))
    run("-i", tone, *meta, "-c:a", "pcm_s16be", os.path.join(out, "signal.aiff"))
    for name, extra in (("noise.mp4", ["-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", "-b:a", "16k"]),
                        ("noise.mov", ["-c:v", "libx264", "-preset", "ultrafast", "-an"]),
                        ("noise.3gp", ["-c:v", "libx264", "-preset", "ultrafast", "-an"]),
                        ("noise.mkv", ["-c:v", "libx264", "-preset", "ultrafast", "-c:a", "libopus", "-b:a", "16k"]),
                        ("noise.webm", ["-c:v", "libvpx", "-b:v", "200k", "-c:a", "libopus", "-b:a", "16k"]),
                        ("noise.avi", ["-c:v", "mpeg4", "-q:v", "2", "-an"]),
                        ("noise.ts", ["-c:v", "libx264", "-preset", "ultrafast", "-an", "-f", "mpegts"])):
        run(*video, "-i", src, "-t", "0.4", *meta, "-pix_fmt", "yuv420p", *extra, os.path.join(out, name))


def fonts(out):
    from fontTools.fontBuilder import FontBuilder
    from fontTools.pens.t2CharStringPen import T2CharStringPen
    from fontTools.pens.ttGlyphPen import TTGlyphPen
    from fontTools.ttLib import TTCollection, TTFont

    def draw(pen, k):
        rnd = random.Random(SEED + k)
        pen.moveTo((100, 0))
        for _ in range(40):
            pen.lineTo((rnd.randrange(1000), rnd.randrange(1000)))
        pen.closePath()

    names = [".notdef", "A", "B", "C"]
    cmap = {ord("A"): "A", ord("B"): "B", ord("C"): "C"}
    meta = {"familyName": "Lazaret Noise", "styleName": "Regular"}

    def build(cff):
        fb = FontBuilder(1000, isTTF=not cff)
        fb.setupGlyphOrder(names)
        fb.setupCharacterMap(cmap)
        if cff:
            glyphs = {}
            for k, n in enumerate(names):
                pen = T2CharStringPen(600, None)
                draw(pen, k)
                glyphs[n] = pen.getCharString()
            fb.setupCFF("LazaretNoise-Regular", {"FullName": "Lazaret Noise"}, glyphs, {})
        else:
            glyphs = {}
            for k, n in enumerate(names):
                pen = TTGlyphPen(None)
                draw(pen, k)
                glyphs[n] = pen.glyph()
            fb.setupGlyf(glyphs)
        fb.setupHorizontalMetrics({n: (600, 0) for n in names})
        fb.setupHorizontalHeader(ascent=800, descent=-200)
        fb.setupNameTable(meta)
        fb.setupOS2()
        fb.setupPost()
        # (a fixed date, so that the files are the same each time they are made)
        fb.font.recalcTimestamp = False
        fb.font["head"].created = fb.font["head"].modified = 3_870_000_000
        buf = io.BytesIO()
        fb.save(buf)
        return buf.getvalue()

    ttf, otf = build(False), build(True)
    with open(os.path.join(out, "noise.ttf"), "wb") as f:
        f.write(ttf)
    with open(os.path.join(out, "noise.otf"), "wb") as f:
        f.write(otf)
    for flavor in ("woff", "woff2"):
        font = TTFont(io.BytesIO(ttf), recalcTimestamp=False)
        font.flavor = flavor
        buf = io.BytesIO()
        font.save(buf)
        with open(os.path.join(out, f"noise.{flavor}"), "wb") as f:
            f.write(buf.getvalue())
    coll = TTCollection()
    coll.fonts = [TTFont(io.BytesIO(ttf), recalcTimestamp=False), TTFont(io.BytesIO(otf), recalcTimestamp=False)]
    buf = io.BytesIO()
    coll.save(buf)
    with open(os.path.join(out, "noise.ttc"), "wb") as f:
        f.write(buf.getvalue())


def imt(out):
    # Pillow's own test image's shape (Tests/images/bw_gradient.imt: a comment, width, height, pixel n8, a form feed,
    # then the rows): a gradient of 256 levels, ten rows
    body = b"*comment\nwidth 256\nheight 10\npixel n8\n\x0c" + bytes(range(256)) * 10
    with open(os.path.join(out, "gradient.imt"), "wb") as f:
        f.write(body)


def manifest(out):
    lines = []
    for name in sorted(os.listdir(out)):
        if name in ("MANIFEST", "README.md"):
            continue
        with open(os.path.join(out, name), "rb") as f:
            lines.append(f"{hashlib.sha256(f.read()).hexdigest()}  {name}\n")
    return "".join(lines)


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise, and
    never raises on a character the stream can't encode (STRUCTURE.md,
    "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main(argv):
    _configure_stdio()
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--check", action="store_true", help="compare the files there with their MANIFEST")
    a = ap.parse_args(argv)
    if a.check:
        with open(os.path.join(a.out, "MANIFEST"), encoding="utf-8") as f:
            want = f.read()
        got = manifest(a.out)
        if got != want:
            print("tests/fixtures/media differs from its MANIFEST", file=sys.stderr)
            return 1
        return 0
    os.makedirs(a.out, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        pillow(a.out)
        ffmpeg(a.out, tmp)
        fonts(a.out)
        imt(a.out)
    with open(os.path.join(a.out, "MANIFEST"), "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest(a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
