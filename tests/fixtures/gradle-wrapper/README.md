# Gradle wrapper fixtures (FP-GRADLE-WRAPPER)

Genuine Gradle wrapper jars, with the `gradle-wrapper.properties` beside them, as three open-source projects
commit them. The jars are Gradle's own (the Gradle Build Tool, Apache License 2.0); each one's SHA-256 is in
Gradle's published wrapper checksums (the rule pack's GRADLE_WRAPPER_CHECKSUMS). The tests that use them
(`rust/crates/lazaret-engine/src/gradle/tests.rs`, `python/tests/scanner/test_review_gradle_wrapper.py`,
`python/tests/registry/test_gradle_wrapper_registry.py`, `js/test/review-gradle-wrapper.test.js`,
`python/tests/architecture/test_js_parity_gradle_wrapper.py`) make the changed copies they need themselves (a byte
changed, a class added). Nothing here is run.

| folder | taken from | commit | jar SHA-256 | Gradle's list has it for | distributionUrl names |
|---|---|---|---|---|---|
| `4.10.3/` | github.com/JakeWharton/butterknife | `fcdebedf3276096db2f51bf6372b849b5a9c75ed` (2020-09-03) | `660ab018b8e319e9ae779fdb1b7ac47d0321bde953bf0eb4545f14952cfdcaa3` | 4.10.3 | 4.10.3 |
| `8.14/` | github.com/mockito/mockito | `220c594adceebf92a0d06e2fb1e4398b25344d46` (2026-10-20) | `7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172` | 8.14 to 8.14.5 and their release candidates | 9.4.1 |
| `9.8/` | github.com/ReactiveX/RxJava | `ee4a29e124976f4f147ae12c7daeb22975057d58` (2026-10-19) | `3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98` | 9.8.1, 9.8.2 | 9.8.1 |

mockito's shows why the check is the jar's checksum alone: its properties name Gradle 9.4.1, its jar is the one
Gradle 8.14 wrote (the jar is regenerated only when `gradle wrapper` runs, not when the distribution is changed).
