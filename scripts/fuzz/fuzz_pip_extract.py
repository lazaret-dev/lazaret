"""What pip writes from an sdist, with this Python's pip: pip's own unpack_file (its untar_file, or unzip_file for a
.zip), as pip unpacks an sdist before it builds it. One JSON line in per archive ({"path": FILE}, the file's name
ending in .tar.gz or .zip), one JSON line out: {"ok": bool, "error": message or null, "files": [[path, sha256,
size], ...]}, the paths `/`-separated and relative to the folder pip unpacked into; a link or anything else that is
not a regular file is listed with "other" for its digest. Run with -I: it needs pip, and nothing else of this
repository. Used by the `archive-pip-diff` fuzz target (BR-4)."""
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile

logging.disable(logging.CRITICAL)

from pip._internal.utils.unpacking import unpack_file  # noqa: E402  (pip's own code, as pip runs it)


def main():
    for line in sys.stdin:
        request = json.loads(line)
        dest = tempfile.mkdtemp(prefix="lz-pip-x-")
        out = {"ok": True, "error": None, "files": []}
        try:
            unpack_file(request["path"], os.path.join(dest, "out"))
        except BaseException as exc:                 # (pip refuses the archive: InstallationError and the like)
            out["ok"], out["error"] = False, f"{type(exc).__name__}: {str(exc)[:200]}"
        root = os.path.join(dest, "out")
        for top, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(top, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if os.path.islink(full) or not os.path.isfile(full):
                    out["files"].append([rel, "other", 0])
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                out["files"].append([rel, hashlib.sha256(data).hexdigest(), len(data)])
        shutil.rmtree(dest, ignore_errors=True)
        sys.stdout.write(json.dumps(out, ensure_ascii=True) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
