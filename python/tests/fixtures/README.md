# Test fixtures: inert by policy

Everything under `tests/fixtures/` is **inert**. A fixture may *look* like a
malicious or vulnerable project (a suspicious install hook, an obfuscated
string, a hardcoded credential, a SQL injection), so the scanner has something
to detect, but it must not do anything harmful:

- Network references point at reserved, non-routable addresses (`192.0.2.0/24`,
  or a `.invalid` host) and never at real services.
- Credentials are dummies, and no line holds a provider's format whole (an AWS
  key id, a Slack, GitHub, Stripe, npm, OpenAI, Anthropic or Google key): a
  test or a fixture that needs one writes it in pieces, or with one character
  escaped (`\x41` for an `A`), so the value is the same and secret scanners,
  GitHub's push protection among them, do not read it as a key.
  `tests/architecture/test_fixture_credentials.py` checks the whole repository.
- Nothing here is ever installed or executed. Tests read these files; they never
  `pip install`, `npm install`, or run them.

Functional offensive samples and real-world malware do **not** belong here.
They live in the private `lazaret-dev/lazaret-samples` repository and reach the
tests only through `LAZARET_SAMPLES_DIR` (see `STRUCTURE.md`, section 6).

These trees are excluded from every published artifact: the wheel and sdist
contain only `src/lazaret/`, and the npm package only `bin/` and `src/`.
