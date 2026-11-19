#!/bin/sh
# Full-history secret scan. Installation belongs to the caller so local and CI
# runs can verify the downloaded executable before this script invokes it.
set -eu

GITLEAKS_VERSION=8.30.1

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks ${GITLEAKS_VERSION} is required" >&2
    exit 2
fi

installed=$(gitleaks version 2>/dev/null || true)
case "$installed" in
    *"${GITLEAKS_VERSION}"*) ;;
    *)
        echo "gitleaks ${GITLEAKS_VERSION} is required; found: ${installed:-unknown}" >&2
        exit 2
        ;;
esac

test -f .gitleaksignore || {
    echo ".gitleaksignore is missing" >&2
    exit 2
}

exec gitleaks git . --redact --no-banner "$@"
