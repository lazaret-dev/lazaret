"""Write python/tests/fixtures/protobuf_es/gen/: what protoc-gen-es writes for the fixture's own .proto files
(proto/), the shapes FP-B64-PROTOBUF passes over: each file's descriptor as base64, handed to fileDesc.

The .proto files are made up for the tests (a listening room, a status enum with many file options, a proto2 file
with defaults, extensions and reserved names, an edition 2023 file). The generators are run, never the generated
code. Needs Node and, in one folder, `npm install @bufbuild/buf @bufbuild/protoc-gen-es@2.16.0 @bufbuild/protobuf@2.16.0
typescript prettier@3`, and in another `npm install @bufbuild/protoc-gen-es@2.0.0` (the codegenv1 form, 2.0 to 2.2):

    python -I scripts/make_protobuf_fixtures.py NODE_MODULES NODE_MODULES_2_0 [OUT]

    gen/ts/       target=ts (2.16.0, codegenv2)              gen/v1/        target=ts (2.0.0, codegenv1)
    gen/js/       target=js+dts, ESM (no .d.ts kept)         gen/cjs/       target=js, js_import_style=legacy_commonjs
    gen/tsc/      gen/ts compiled by tsc to CommonJS          gen/prettier/  gen/ts formatted by prettier
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "python", "tests", "fixtures", "protobuf_es")


def main(argv):
    sys.path.insert(0, os.path.join(HERE, "..", "python", "src"))
    from lazaret.scanner.core import configure_stdio
    configure_stdio()
    if len(argv) < 2:
        print(__doc__)
        return 2
    mods, mods20 = (os.path.abspath(a) for a in argv[:2])
    out = os.path.abspath(argv[2]) if len(argv) > 2 else os.path.join(FIXTURE, "gen")
    bin_ = os.path.join(mods, ".bin")
    es, es20 = os.path.join(bin_, "protoc-gen-es"), os.path.join(mods20, ".bin", "protoc-gen-es")
    proto = os.path.join(FIXTURE, "proto")
    with tempfile.TemporaryDirectory() as tmp:
        plugins = [(es, "ts", ["target=ts"]), (es, "js", ["target=js+dts"]),
                   (es, "cjs", ["target=js", "js_import_style=legacy_commonjs"]), (es20, "v1", ["target=ts"])]
        lines = ["version: v2", "plugins:"]
        for plugin, name, opts in plugins:
            lines += [f"  - local: {plugin}", f"    out: {os.path.join(tmp, name)}", f"    opt: [{', '.join(opts)}]"]
        template = os.path.join(tmp, "buf.gen.yaml")
        with open(template, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        with open(os.path.join(tmp, "buf.yaml"), "w", encoding="utf-8") as f:
            f.write("version: v2\n")
        shutil.copytree(proto, os.path.join(tmp, "src"))
        shutil.copy(os.path.join(tmp, "buf.yaml"), os.path.join(tmp, "src", "buf.yaml"))
        subprocess.run([os.path.join(bin_, "buf"), "generate", "--template", template], cwd=os.path.join(tmp, "src"),
                       check=True, env={**os.environ, "PATH": bin_ + os.pathsep + os.environ.get("PATH", "")})
        subprocess.run([os.path.join(bin_, "tsc"), "--module", "commonjs", "--target", "es2020", "--skipLibCheck",
                        "--moduleResolution", "node", "--outDir", os.path.join(tmp, "tsc"), "--rootDir",
                        os.path.join(tmp, "ts")] + [os.path.join(r, n) for r, _, ns in os.walk(os.path.join(tmp, "ts"))
                                                    for n in ns if n.endswith(".ts")], cwd=os.path.dirname(mods))
        os.makedirs(os.path.join(tmp, "prettier"))
        shutil.copy(os.path.join(tmp, "ts", "listentogether", "v1", "listentogether_pb.ts"), os.path.join(tmp, "prettier"))
        subprocess.run([os.path.join(bin_, "prettier"), "--write", os.path.join(tmp, "prettier", "listentogether_pb.ts")],
                       check=True, stdout=subprocess.DEVNULL)
        shutil.rmtree(out, ignore_errors=True)
        for name in ("ts", "js", "cjs", "v1", "tsc", "prettier"):
            for root, _dirs, names in os.walk(os.path.join(tmp, name)):
                for n in names:
                    if n.endswith(".d.ts"):
                        continue
                    rel = os.path.relpath(os.path.join(root, n), tmp)
                    os.makedirs(os.path.dirname(os.path.join(out, rel)), exist_ok=True)
                    shutil.copy(os.path.join(root, n), os.path.join(out, rel))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
