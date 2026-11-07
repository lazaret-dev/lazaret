# lazaret.dev

This directory is the reviewed source deployed at <https://lazaret.dev>.
It is a static site: `index.html`, `style.css`, `favicon.svg`, and the
Cloudflare Pages `_headers` file are the complete deployable contents.

## Review locally

From the repository root:

```sh
python3 -m http.server --directory website 8000
```

Then open <http://127.0.0.1:8000/>. Before deployment, check that all local
assets referenced by `index.html` exist and that the install, capability,
benchmark, package-registry, and release wording agrees with `README.md`,
`python/README.md`, `js/README.md`, and `CHANGELOG.md`.

## Deployment boundary

Deploy this directory to the existing Cloudflare Pages project only after the
corresponding repository change is reviewed. Account names, tokens, generated
Wrangler state, and local environment files do not belong in this repository.
Use the project's configured deployment path or the Cloudflare dashboard; do
not create or change a Pages project, domain, DNS record, or credential merely
from these instructions.

`.wrangler/`, `.dev.vars`, and `.DS_Store` are ignored. Do not add an empty
`404.html`: if the Pages project needs a custom 404 response, commit and review
the real page.
