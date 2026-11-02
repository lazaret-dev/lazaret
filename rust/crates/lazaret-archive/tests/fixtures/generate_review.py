"""Small, inert local parser cases; never executes or deserializes archive payloads."""
from pathlib import Path
import bz2, gzip, importlib.util, io, json, lzma, struct, tarfile

FIX = Path(__file__).resolve().parent
OUT = FIX / 'review'
OUT.mkdir(exist_ok=True)

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, FIX / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

seven = load('seven_generator', 'generate_7z.py')
rar = load('rar_generator', 'generate.py')

def put(name, data, expected=None):
    (OUT / name).write_bytes(data)
    if expected is not None:
        (OUT / (name + '.expected')).write_bytes(expected)

for codec, method, props in [(lzma.FILTER_LZMA1, seven.LZMA1, b'\x5a\x00\x00\x10\x00'),
                             (lzma.FILTER_LZMA2, seven.LZMA2, b'\x10')]:
    raw = b'abcdefgh' * 500
    packed = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[{'id': codec, 'dict_size': 1 << 20, 'lc': 0, 'lp': 0, 'pb': 2}])
    assert lzma.decompress(packed, format=lzma.FORMAT_RAW, filters=[{'id': codec, 'dict_size': 1 << 20, 'lc': 0, 'lp': 0, 'pb': 2}]) == raw
    put(f'lc0-{codec}.7z', seven.single(method, props, packed, raw), raw)

a, b = b'abcdefghZ' * 500, b'next-context' * 500
pa, props = seven.raw_lzma2(a)
pb, _ = seven.raw_lzma2(b)
packed = pa[:-1] + pb
assert lzma.decompress(packed, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}]) == a + b
put('dictionary-reset.7z', seven.single(seven.LZMA2, props, packed, a + b), a + b)

put('exact-limit.lzma', (FIX / 'pickle.lzma').read_bytes(), (FIX / 'pickle.pkl').read_bytes())
put('zero-limit.lzma', lzma.compress(b'', format=lzma.FORMAT_ALONE), b'')

# Forge a known-size LZMA-alone declaration and remove the EOS bytes.
raw = b'hello world'
alone = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE))
alone[5:13] = struct.pack('<Q', len(raw))
for cut in range(9):
    put(f'known-size-cut-{cut}.lzma', bytes(alone[:len(alone)-cut]) if cut else bytes(alone), raw)

def tar_entries(entries, pax=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as t:
        for name, raw in entries:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            if pax: info.pax_headers = pax
            t.addfile(info, io.BytesIO(raw))
    return buf.getvalue()

put('pax-sparse.tar', tar_entries([('stored.txt', b'TEST')], {'GNU.sparse.map': '0,4', 'GNU.sparse.size': '10', 'GNU.sparse.name': 'actual.txt'}), b'TEST' + b'\0' * 6)
put('pax-sparse-traversal.tar', tar_entries([('stored.txt', b'TEST')], {'GNU.sparse.map': '0,4', 'GNU.sparse.size': '10', 'GNU.sparse.name': '../actual.txt'}))
put('empty.tar', b'\0' * 10240, b'')
put('empty.tar.gz', gzip.compress(b'\0' * 10240))
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w') as t:
    i=tarfile.TarInfo('./'); i.type=tarfile.DIRTYPE; t.addfile(i)
    i=tarfile.TarInfo('./a.txt'); i.size=4; t.addfile(i, io.BytesIO(b'TEST'))
put('root-dot-slash.tar', buf.getvalue(), b'TEST')
put('case-collision.tar', tar_entries([('File.txt', b'A'), ('file.txt', b'B')]), b'AB')
put('ancestor-collision.tar', tar_entries([('a', b'A'), ('a/b', b'B')]), b'AB')

# A stored 7-Zip symlink: Unix mode is in the upper 16 attribute bits.
raw = b'../target'
info = seven.files_info(['link'])
attr = b'\x01\x00' + struct.pack('<I', (0o120777 << 16) | 0x8000)
info = info[:-1] + b'\x15' + seven.uint(len(attr)) + attr + b'\0'
header = b'\x01\x04' + seven.streams([seven.folder(seven.COPY, b'', len(raw))], [len(raw)], substreams=[[raw]]) + info + b'\0'
put('symlink.7z', seven.container(header, raw))

# Small valid archives expose repeated prefix summation in decode_folder.
for n in [1000, 2000, 4000, 8000, 16000, 32000]:
    h = seven.plain_header([f'f{i}' for i in range(n)], [seven.folder(seven.COPY, b'', 1)] * n, [1] * n)
    put(f'folders-{n}.7z', seven.container(h, b'x' * n))

# Many short independent bzip2 blocks and regular mixed-input codec samples.
for i, raw in enumerate([b'', b'x', b'x'*10000, bytes(range(256))*1000, bytes(range(255,-1,-1))*4000]):
    for ext, packed in [('bz2', bz2.compress(raw)), ('xz', lzma.compress(raw)), ('lzma', lzma.compress(raw, format=lzma.FORMAT_ALONE))]:
        put(f'differential-{i}.{ext}', packed, raw)

print(json.dumps({'cases': len([p for p in OUT.iterdir() if not p.name.endswith('.expected')]), 'directory': str(OUT)}, indent=2))
