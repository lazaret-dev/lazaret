#!/usr/bin/env sh
# Runs the Python test suite on this Linux/macOS machine the way CI's other
# platforms would see it, so host-default bugs show up before CI does
# (STRUCTURE.md, "Cross-platform rules"). It is a simulation, not a
# substitute: the full OS x Python matrix in CI is still the gate.
#
#   sh scripts/simulate-platforms.sh            # every python3.10+ on PATH
#   sh scripts/simulate-platforms.sh python3.12 # just these
#
# For each interpreter, three runs of `unittest discover`:
#   windows-like  a non-UTF-8 locale with UTF-8 mode and locale coercion off
#                 (PYTHONUTF8=0 PYTHONCOERCECLOCALE=0): the host default
#                 encoding becomes Latin-1 (the closest Linux has to Windows'
#                 cp1252; create it once with
#                 `localedef -i en_US -f ISO-8859-1 en_US.ISO-8859-1`) or, if
#                 no Latin-1 locale is installed, ASCII (LC_ALL=C). Anything
#                 that relies on the host default (open() without encoding=,
#                 subprocess text=True, a CLI printing to a pipe) fails here as
#                 it would on Windows. Under ASCII, tests that need non-ASCII
#                 file names skip (the filesystem can't hold them).
#   macos-like    TMPDIR behind a symlink, like macOS's /var -> /private/var,
#                 so path comparisons that don't resolve both sides fail.
#   non-root      only when run as root: the suite as an unprivileged user,
#                 as on CI runners (permission tests skip under root).
# A run that passes but prints a ResourceWarning (a file, socket or database
# left open: fine here, a failed delete on Windows) counts as failed too.
# Exit status: 1 if any run failed.
set -u
cd "$(dirname "$0")/../python"

if [ "$#" -gt 0 ]; then
  pythons="$*"
else
  pythons=""
  for v in 3.10 3.11 3.12 3.13 3.14 3.15; do
    command -v "python$v" >/dev/null 2>&1 && pythons="$pythons python$v"
  done
fi
[ -n "$pythons" ] || { echo "no python3.10+ found on PATH" >&2; exit 2; }

work=$(mktemp -d)
chmod 755 "$work"                     # the non-root run must reach its copy
trap 'rm -rf "$work"' EXIT INT TERM
latin1=$(locale -a 2>/dev/null | grep -iE '^[a-z_]+\.(iso-?8859-?1|iso88591)$' | head -n 1)
winloc=${latin1:-C}
mkdir "$work/real" && ln -s "$work/real" "$work/link"
failed=0

run() {  # label, command...
  label=$1; shift
  printf '%-34s ' "$label"
  if out=$("$@" -m unittest discover -s tests -t . 2>&1); then
    leaks=$(printf '%s\n' "$out" | grep -E 'ResourceWarning: unclosed' | sed 's/^[.sExF]*//' | cut -c1-160 | sort | uniq -c)
    if [ -n "$leaks" ]; then
      failed=1
      echo "LEAK $(printf '%s\n' "$out" | grep -E '^Ran ' | tail -n 1)"
      printf '%s\n' "$leaks" | sed 's/^/    /'
    else
      echo "ok   $(printf '%s\n' "$out" | grep -E '^Ran ' | tail -n 1)"
    fi
  else
    failed=1
    echo "FAIL"
    detail=$(printf '%s\n' "$out" | grep -E '^(FAIL|ERROR):|^Ran |^FAILED')
    # no test summary: the run itself failed (e.g. the interpreter lives under
    # /root, which the unprivileged user can't read) - show why
    [ -n "$detail" ] || detail=$(printf '%s\n' "$out" | tail -n 5)
    printf '%s\n' "$detail" | sed 's/^/    /'
  fi
}

for py in $pythons; do
  run "$py windows-like ($winloc)" \
    env LC_ALL="$winloc" LANG="$winloc" PYTHONUTF8=0 PYTHONCOERCECLOCALE=0 PYTHONIOENCODING= "$py"
  run "$py macos-like (symlinked TMPDIR)" env TMPDIR="$work/link" "$py"
  if [ "$(id -u)" = 0 ] && command -v runuser >/dev/null 2>&1; then
    copy="$work/nonroot"
    rm -rf "$copy" && cp -R .. "$copy" && chown -R nobody "$copy" "$work/real" 2>/dev/null
    run "$py non-root" sh -c "cd '$copy/python' && exec runuser -u nobody -- env HOME='$copy' PYTHONDONTWRITEBYTECODE=1 \"\$0\" \"\$@\"" "$py"
  fi
done
exit "$failed"
