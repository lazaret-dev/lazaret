//! Live secret verification's logic (V-1 stage 2): the table as the pack holds it, which provider a credential is,
//! the requests (AWS's signature held to the vectors AWS publishes, and to stage 1's Python signer), and the reading
//! of answers. The packages' tests hold the rest (python/tests/scanner/test_secretverify.py), through the calls.

use super::*;
use crate::pack;

fn table_now() -> Vec<String> {
    match table(&pack::current()) {
        Ok(t) => t.iter().map(|q| q.id.clone()).collect(),
        Err(m) => panic!("{m}"),
    }
}

fn provider(id: &str) -> std::sync::Arc<crate::pack::Pack> {
    let p = pack::current();
    by_id(&p, id).unwrap();
    p
}

fn ask(id: &str, parts: &[(&str, &str)]) -> Result<Request, &'static str> {
    let p = provider(id);
    let q = by_id(&p, id).unwrap();
    let parts: Vec<(String, Vec<u32>)> = parts.iter().map(|(n, v)| (n.to_string(), cps(v))).collect();
    request(q, &parts, "20261003T120000Z")
}

fn pairs(h: &[(&str, &str)]) -> Vec<(String, String)> {
    h.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
}

const GITHUB: &str = "gh\x70_a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2";
const AWS_ID: &str = "AKI\x41ABCDEFGHIJKLMNOP";
const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDEN\x47+bPxRfiCYEXAMPLEKEY";

// ------------------------------------------------------------------------------------------------ the table

#[test]
fn the_packs_table_is_the_seven_providers() {
    assert_eq!(table_now(), ["github", "slack", "stripe", "npm", "openai", "anthropic", "aws"]);
    let p = pack::current();
    let hosts: Vec<&str> = table(&p).as_ref().unwrap().iter().map(|q| q.host.as_str()).collect();
    assert_eq!(hosts, ["api.github.com", "slack.com", "api.stripe.com", "registry.npmjs.org", "api.openai.com",
                       "api.anthropic.com", "sts.amazonaws.com"]);
}

#[test]
fn a_host_is_a_lower_case_dns_name_with_a_dot() {
    for good in ["api.github.com", "x.zz", "a-b.example.co.uk", "xn--bcher-kva.example"] {
        assert!(is_host(good), "{good}");
    }
    let longest = [&*"a".repeat(63), &*"a".repeat(63), &*"a".repeat(63), &*"b".repeat(61)].join(".");
    assert_eq!(longest.len(), 253);
    assert!(is_host(&longest));
    for bad in ["", "localhost", "API.github.com", "127.0.0.1", "api.github.com.", "api.github.com:443", "a b.com", "-a.example.com",
                "a-.example.com", "a..example.com", ".example.com", "example.123", "example.c", &format!("{longest}b")] {
        assert!(!is_host(bad), "{bad}");
    }
}

fn entry(json_text: &str) -> Result<Provider, String> {
    provider_of(&crate::json::parse_str(json_text).unwrap())
}

const GOOD: &str = r#"{"id": "x", "label": "X", "parts": {"secret": "x_[a-z]+"}, "host": "api.x.example",
    "request": {"method": "GET", "path": "/me", "query": {}, "headers": {"Authorization": "Bearer {secret}"}},
    "answers": [{"status": [200], "outcome": "live"}]}"#;

#[test]
fn an_entry_is_checked_as_secretverify_validate_checks_it() {
    assert!(entry(GOOD).is_ok());
    for (from, to, why) in [
        (r#""id": "x""#, r#""id": "X""#, "provider id"),
        (r#""label": "X""#, r#""label": """#, "label"),
        (r#""x_[a-z]+""#, r#""([""#, "compile"),
        (r#""secret": "x_"#, r#""token": "x_"#, "secret"),
        (r#""api.x.example""#, r#""localhost""#, "host"),
        (r#""GET""#, r#""PUT""#, "method"),
        (r#""/me""#, r#""/me/{secret}""#, "path"),
        (r#""query": {}"#, r#""query": {"k": "{secret}"}"#, "query"),
        (r#""Bearer {secret}""#, r#""Bearer {nothing}""#, "not one"),
        (r#""Bearer {secret}""#, r#""Bearer x""#, "sent nowhere"),
        (r#"{"Authorization": "Bearer {secret}"}"#, r#"["Authorization"]"#, "not text"),
        (r#""headers""#, r#""body": "a={secret}", "headers""#, "POST"),
        (r#""outcome": "live""#, r#""outcome": "maybe""#, "answer rule"),
        (r#""status": [200]"#, r#""status": [600]"#, "status"),
        (r#""status": [200]"#, r#""status": [true]"#, "status"),
        (r#""outcome": "live"}"#, r#""outcome": "rejected", "who": {"json": "a"}}"#, "who"),
    ] {
        let changed = GOOD.replace(from, to);
        assert_ne!(changed, GOOD, "{from}");
        match entry(&changed) {
            Err(m) => assert!(m.contains(why), "{from} -> {to}: {m}"),
            Ok(_) => panic!("{from} -> {to} was taken"),
        }
    }
    // a signed request is signed with an id and a secret, and does not send its secret
    let signed = GOOD.replace(r#""parts": {"secret": "x_[a-z]+"}"#, r#""parts": {"id": "i", "secret": "s"}"#)
        .replace(r#""query": {}"#, r#""query": {}, "sigv4": {"service": "sts", "region": "us-east-1"}"#);
    assert!(entry(&signed).unwrap_err().contains("does not send"));
    assert!(entry(&signed.replace("Bearer {secret}", "{id}")).is_ok());
}

// ------------------------------------------------------------------------------------------------ which provider

fn ids(text: &str) -> Vec<String> {
    let p = pack::current();
    identify(table(&p).as_ref().unwrap(), &cps(text))
}

#[test]
fn each_sample_names_its_provider_alone() {
    for (id, sample) in [("github", GITHUB), ("slack", "xox\x62-1234567890-abcdefghij"), ("stripe", "sk_liv\x65_a1a1a1a1a1a1a1a1a1a1a1a1"),
                         ("npm", "np\x6d_A1b2A1b2A1b2A1b2A1b2A1b2A1b2A1b2A1b2"), ("openai", "sk-proj-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"),
                         ("anthropic", "sk-an\x74-api03-Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_")] {
        assert_eq!(ids(sample), [id], "{sample}");
    }
    assert!(ids(AWS_ID).is_empty() && ids(AWS_SECRET).is_empty(), "a pair is not named by a part");
    assert_eq!(ids(&format!("sk-ant-{}", "a".repeat(30))), ["anthropic"]);
    assert_eq!(ids(&format!("sk-ant{}", "a".repeat(30))), ["openai"]);
}

#[test]
fn the_lengths_are_the_formats_and_a_credential_is_looked_at_to_512_characters() {
    for (prefix, low, high) in [("ghp_", 36, 251), ("github_pat_", 22, 255), ("xoxb-", 10, 250), ("sk_live_", 16, 247), ("npm_", 36, 36),
                                ("sk-", 20, 200), ("sk-ant-", 20, 200)] {
        assert!(!ids(&format!("{prefix}{}", "a".repeat(low))).is_empty(), "{prefix}");
        assert!(!ids(&format!("{prefix}{}", "a".repeat(high))).is_empty(), "{prefix}");
        assert!(ids(&format!("{prefix}{}", "a".repeat(low - 1))).is_empty(), "{prefix}");
        assert!(ids(&format!("{prefix}{}", "a".repeat(high + 1))).is_empty(), "{prefix}");
    }
    let wide = entry(&GOOD.replace("x_[a-z]+", "[a-z]+")).unwrap();
    assert_eq!(identify(std::slice::from_ref(&wide), &cps(&"a".repeat(512))), ["x"]);
    assert!(identify(std::slice::from_ref(&wide), &cps(&"a".repeat(513))).is_empty());
    let parts = |n: usize| vec![("secret".to_string(), cps(&"a".repeat(n)))];
    assert!(request(&wide, &parts(512), "20261003T120000Z").is_ok());
    assert_eq!(request(&wide, &parts(513), "20261003T120000Z").unwrap_err(), NOT_THIS_FORMAT);
}

#[test]
fn what_is_not_a_credential_is_none() {
    for text in [format!("{GITHUB}\n"), format!("{GITHUB} "), format!(" {GITHUB}"), format!("{GITHUB}\r\nX-Evil: 1"),
                 format!("{}é", &GITHUB[..GITHUB.len() - 1]), GITHUB.to_uppercase(), format!("xxx{GITHUB}"), String::new()] {
        assert!(ids(&text).is_empty(), "{text:?}");
    }
}

// ------------------------------------------------------------------------------------------------ the requests

#[test]
fn each_request_is_stage_ones() {
    // (recorded from stage 1's Python, lazaret/scanner/secretverify.py's build_request, at 2026-10-03T12:00:00Z)
    let r = ask("github", &[("secret", GITHUB)]).unwrap();
    assert_eq!((r.method.as_str(), r.host.as_str(), r.path.as_str(), r.body.as_deref()), ("GET", "api.github.com", "/user", None));
    let mut headers = r.headers.clone();
    headers.sort();
    assert_eq!(headers, pairs(&[("Accept", "application/vnd.github+json"), ("Authorization", &format!("Bearer {GITHUB}")),
                                ("User-Agent", "lazaret-secret-verify"), ("X-GitHub-Api-Version", "2022-11-28")]));
    assert_eq!(r.secret_headers, ["Authorization"]);
    let r = ask("anthropic", &[("secret", "sk-an\x74-api03-Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_")]).unwrap();
    assert_eq!(r.secret_headers, ["x-api-key"]);
    let r = ask("aws", &[("id", AWS_ID), ("secret", AWS_SECRET)]).unwrap();
    assert_eq!((r.method.as_str(), r.host.as_str(), r.path.as_str()), ("POST", "sts.amazonaws.com", "/"));
    assert_eq!(r.body.as_deref(), Some("Action=GetCallerIdentity&Version=2011-06-15"));
    let auth = &r.headers.iter().find(|(n, _)| n == "authorization").unwrap().1;
    assert_eq!(auth, "AWS4-HMAC-SHA256 Credential=AKI\x41ABCDEFGHIJKLMNOP/20261003/us-east-1/sts/aws4_request, \
                      SignedHeaders=accept;content-type;host;user-agent;x-amz-date, \
                      Signature=7fe52775358f0f7ebee0fa0156d578e8b5a5df50d904ea761d84447ae68f3134");
    assert_eq!(r.headers.iter().find(|(n, _)| n == "x-amz-date").unwrap().1, "20261003T120000Z");
    assert!(!r.headers.iter().any(|(_, v)| v.contains(AWS_SECRET)), "a signed request does not send its secret");
    assert_eq!(r.secret_headers, ["authorization"]);
}

#[test]
fn a_credential_not_in_the_format_is_not_sent() {
    for parts in [vec![("secret", "ghp_short")], vec![("secret", &*format!("{GITHUB}\n"))], vec![("secret", GITHUB), ("id", "x")],
                  vec![("token", GITHUB)], vec![]] {
        assert_eq!(ask("github", &parts).unwrap_err(), NOT_THIS_FORMAT, "{parts:?}");
    }
    assert_eq!(ask("aws", &[("secret", AWS_SECRET)]).unwrap_err(), NOT_THIS_FORMAT);
}

#[test]
fn a_query_in_an_entry_is_encoded_and_sorted() {
    let q = entry(&GOOD.replace(r#""query": {}"#, r#""query": {"b": "x y", "a": "é/"}"#)).unwrap();
    let r = request(&q, &[("secret".to_string(), cps("x_abc"))], "20261003T120000Z").unwrap();
    assert_eq!(r.path, "/me?a=%C3%A9%2F&b=x%20y");
}

// AWS's published vectors (its signature test suite and the IAM documentation), as stage 1's tests held its signer.
const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDEN\x47+bPxRfiCYEXAMPLEKEY";

fn authorization(method: &str, query: &[(&str, &str)], body: &[u8], headers: &[(&str, &str)], host: &str, service: &str) -> String {
    let out = sigv4(method, host, "/", &pairs(query), body, &pairs(headers), ACCESS, SECRET, "us-east-1", service, "20150830T123600Z");
    out.iter().find(|(n, _)| n == "authorization").unwrap().1.clone()
}

fn signed(headers: &str, signature: &str, service: &str) -> String {
    format!("AWS4-HMAC-SHA256 Credential={ACCESS}/20150830/us-east-1/{service}/aws4_request, SignedHeaders={headers}, Signature={signature}")
}

#[test]
fn the_signature_is_aws_published_one() {
    assert_eq!(hex(&signing_key(SECRET, "20150830", "us-east-1", "iam")),
               "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
    let host = "example.amazonaws.com";
    assert_eq!(authorization("GET", &[], b"", &[], host, "service"),
               signed("host;x-amz-date", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", "service"));
    assert_eq!(authorization("POST", &[], b"", &[], host, "service"),
               signed("host;x-amz-date", "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b", "service"));
    assert_eq!(authorization("GET", &[("Param2", "value2"), ("Param1", "value1")], b"", &[], host, "service"),
               signed("host;x-amz-date", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500", "service"));
    assert_eq!(authorization("POST", &[], b"Param1=value1", &[("Content-Type", "application/x-www-form-urlencoded")], host, "service"),
               signed("content-type;host;x-amz-date", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a", "service"));
    assert_eq!(authorization("GET", &[("Action", "ListUsers"), ("Version", "2010-05-08")], b"",
                             &[("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")], "iam.amazonaws.com", "iam"),
               signed("content-type;host;x-amz-date", "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", "iam"));
}

#[test]
fn what_is_signed_is_the_request_and_a_field_is_signed_trimmed_in_lower_case() {
    let base = authorization("POST", &[], b"a=1", &[], "h.amazonaws.com", "sts");
    assert_ne!(base, authorization("POST", &[], b"a=2", &[], "h.amazonaws.com", "sts"));
    assert_ne!(base, authorization("GET", &[], b"a=1", &[], "h.amazonaws.com", "sts"));
    assert_ne!(base, authorization("POST", &[], b"a=1", &[], "o.amazonaws.com", "sts"));
    assert_ne!(base, authorization("POST", &[("x", "1")], b"a=1", &[], "h.amazonaws.com", "sts"));
    assert_ne!(base, authorization("POST", &[], b"a=1", &[("X-Extra", "1")], "h.amazonaws.com", "sts"));
    assert_eq!(authorization("GET", &[], b"", &[("X-Extra", "  a   b  ")], "h.amazonaws.com", "s"),
               authorization("GET", &[], b"", &[("x-extra", "a b")], "h.amazonaws.com", "s"));
    assert!(is_amz_date("20261003T120000Z") && !is_amz_date("2026-10-03T12:00:00Z") && !is_amz_date("20261003T120000"));
}

#[test]
fn hmac_is_rfc_4231s() {
    // test cases 1, 2 and 6 (a key longer than the block)
    assert_eq!(hex(&hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    assert_eq!(hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

// ------------------------------------------------------------------------------------------------ the answers

fn judged(id: &str, status: i64, body: &str, truncated: bool) -> (&'static str, String, Option<String>) {
    let p = provider(id);
    let q = by_id(&p, id).unwrap();
    let (o, d, w) = judge(q.rules(), status, body.as_bytes(), truncated, &[cps(GITHUB)]);
    (o.as_str(), pystr::to_string(&d), w.map(|w| pystr::to_string(&w)))
}

#[test]
fn an_answer_is_read_by_the_first_rule_that_holds() {
    assert_eq!(judged("github", 200, r#"{"login": "octocat"}"#, false), ("live", "HTTP 200".into(), Some("octocat".into())));
    assert_eq!(judged("github", 401, "", false), ("rejected", "GitHub says the token is not valid".into(), None));
    assert_eq!(judged("github", 418, "", false), ("unknown", "the answer was not one this module knows (HTTP 418)".into(), None));
    assert_eq!(judged("github", 502, "", false), ("unknown", "the provider failed (HTTP 502)".into(), None));
    assert_eq!(judged("slack", 200, r#"{"ok": true, "user": "bot"}"#, false).2, Some("bot".into()));
    assert_eq!(judged("slack", 200, r#"{"ok": false, "error": "invalid_auth"}"#, false).0, "rejected");
    assert_eq!(judged("slack", 200, r#"{"ok": "true"}"#, false).0, "unknown");
    assert_eq!(judged("slack", 200, r#"{"ok": true, "user": "bot"}"#, true).0, "unknown", "a body cut short holds no condition");
    assert!(judged("slack", 200, "{}", true).1.contains("larger than 65536 bytes"));
    assert_eq!(judged("stripe", 403, r#"{"error": {"type": "permission_error"}}"#, false).0, "live");
    let arn = "<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/alice</Arn></GetCallerIdentityResult>";
    assert_eq!(judged("aws", 200, arn, false).2, Some("arn:aws:iam::123456789012:user/alice".into()));
    let error = |code: &str| format!("<ErrorResponse><Error><Code>{code}</Code></Error></ErrorResponse>");
    assert_eq!(judged("aws", 403, &error("InvalidClientTokenId"), false).0, "rejected");
    assert_eq!(judged("aws", 400, &error("Throttling"), false).0, "unknown");
    assert_eq!(judged("aws", 403, &error("Other"), false).1, "the answer was not one this module knows (HTTP 403)");
}

#[test]
fn a_duplicate_key_counts_by_its_last_value_as_pythons_json_reads_it() {
    assert_eq!(judged("slack", 200, r#"{"ok": false, "ok": true, "user": "a", "user": "b"}"#, false), ("live", "HTTP 200".into(), Some("b".into())));
}

#[test]
fn what_an_answer_says_is_safe_to_print_and_never_the_credential() {
    assert_eq!(judged("github", 200, "{\"login\": \"\\u001b[31mred\\u2028line\\u202e\"}", false).2, Some("?[31mred?line?".into()));
    assert_eq!(judged("github", 200, &format!(r#"{{"login": "{}"}}"#, "x".repeat(500)), false).2, Some("x".repeat(MAX_WHO)));
    assert_eq!(judged("github", 200, &format!(r#"{{"login": "user-{GITHUB}-x"}}"#), false).2, Some("user-[redacted]-x".into()));
    assert_eq!(pystr::to_string(&safe_text(&cps("abc"), &[cps(""), cps("b")]).unwrap()), "a[redacted]c");
    assert_eq!(safe_text(&[], &[]), None);
}

#[test]
fn a_part_is_found_in_all_of_the_text_before_it_is_cut() {
    let shown = |value: &str, parts: &[&str]| {
        pystr::to_string(&safe_text(&cps(value), &parts.iter().map(|p| cps(p)).collect::<Vec<_>>()).unwrap())
    };
    // a long part that starts in the first 80 characters and runs past the 320 stage 1 looked in: none of it is kept
    let long = "A".repeat(300);
    assert_eq!(shown(&format!("{}{long}", "x".repeat(70)), &[&long]), format!("{}[redacted]", "x".repeat(70)));
    // what comes after a part is shown up to 80 characters, however far into the text
    assert_eq!(shown(&format!("{long}{}", "y".repeat(400)), &[&long]), format!("[redacted]{}", "y".repeat(70)));
    // parts that overlap or sit side by side are one run, and no character of either is kept
    assert_eq!(shown("<abcdef>", &["abc", "bcdef"]), "<[redacted]>");
    assert_eq!(shown("<abcbcdef>", &["abc", "bcdef"]), "<[redacted]>");
    assert_eq!(shown("abc-bcdef", &["abc", "bcdef"]), "[redacted]-[redacted]");
    // a part is looked for in the text as shown: a control character shown as "?" does not hide one
    assert_eq!(shown("a\u{1}c", &["a?c"]), "[redacted]");
    // the run that ends the 80 characters is cut with them
    assert_eq!(shown(&format!("{}{long}", "x".repeat(75)), &[&long]), format!("{}[reda", "x".repeat(75)));
}

#[test]
fn hostile_answers_are_read_without_fault() {
    let deep = "[".repeat(70_000);
    let nested = r#"{"a":"#.repeat(30_000);
    for body in ["", "\u{0}", &deep, &nested, "NaN", "1e999999", r#"{"ok": NaN}"#, &"<Code>".repeat(1000), "\u{feff}{}"] {
        for id in ["github", "slack", "aws"] {
            for status in [200, 403, 0, 999] {
                let (o, d, w) = judged(id, status, body, false);
                assert!(["live", "rejected", "unknown"].contains(&o) && !d.is_empty() && w.map_or(true, |w| !w.is_empty()));
            }
        }
    }
    // bytes that are not UTF-8: no JSON, and the text read with one U+FFFD for each bad sequence
    let p = provider("github");
    let (o, _, w) = judge(by_id(&p, "github").unwrap().rules(), 200, b"{\"login\": \"\xff\"}", false, &[]);
    assert_eq!((o, w), (Outcome::Live, None));
}
