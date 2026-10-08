# The manual live check of secret verification

`verifylive.py` holds the provider table (the rule pack's `_VERIFY_PROVIDERS`, `rust/crates/lazaret-engine/rules/lazaret-rules.json`, which the engine reads) to the real services. It is the
check to run before a release that ships `--verify-secrets`, and again when a provider changes its API. CI never runs it: the
tests (`tests/scanner/test_secretverify*.py`) answer from a stub.

```
python3 scripts/verifylive/verifylive.py --list
python3 scripts/verifylive/verifylive.py --yes
LAZARET_VERIFY_GITHUB=ghp_... LAZARET_VERIFY_NPM=npm_... python3 scripts/verifylive/verifylive.py --yes --only github,npm
```

For each provider it asks about a made-up credential in the provider's format, which the provider must call not valid
(`rejected`), and about the one in your environment, which must be `live` (set `LAZARET_VERIFY_<ID>_EXPECT=rejected` for a key
you have revoked, which checks "rejected" against a real account too). AWS takes `LAZARET_VERIFY_AWS_ID` and
`LAZARET_VERIFY_AWS_SECRET`. Nothing is sent without `--yes`; nothing but the providers in `--list` is called; no credential
is printed.

| provider | the call | made-up key says | a live key says |
|---|---|---|---|
| github | `GET api.github.com/user` | 401 | 200 and the login |
| slack | `GET slack.com/api/auth.test` | 200 `invalid_auth` | 200 `ok` and the user |
| stripe | `GET api.stripe.com/v1/balance` | 401 | 200 (or 403 `permission_error` for a restricted key) |
| npm | `GET registry.npmjs.org/-/whoami` | 401 | 200 and the username |
| openai | `GET api.openai.com/v1/models` | 401 `invalid_api_key` | 200 |
| anthropic | `GET api.anthropic.com/v1/models` | 401 `authentication_error` | 200 (or 403 `permission_error`) |
| aws | `POST sts.amazonaws.com` `GetCallerIdentity`, signed | 403 `InvalidClientTokenId` | 200 and the ARN |

The table's answers are from each provider's documentation; the first run of this script is what confirms them. A line marked
`<-- not what was expected` means the table is wrong for that provider (or the provider changed): read its documentation, change
the table and its tests, and run this again.

OpenAI's key is a user, project or service account key (`sk-`, `sk-proj-`, `sk-svcacct-`), Anthropic's an API key
(`sk-ant-api03-`). Admin keys (OpenAI's `sk-admin-`, Anthropic's `sk-ant-admin01-` and Claude Enterprise's `sk-ant-api01-`,
which are its Compliance Access Keys too) and Anthropic's OAuth tokens (`sk-ant-oat01-`) are not asked about: `/v1/models` is
not documented for them, and a 401 there could read as "rejected" for a key that is live. A 401 without the provider's own
error (`invalid_api_key`, `authentication_error`) is `unknown`, never `rejected`.
