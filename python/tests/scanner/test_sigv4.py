"""AWS Signature Version 4 (scanner/sigv4.py), held to the vectors AWS publishes: the signing-key example of the documentation and
cases of its signature test suite (`get-vanilla`, `post-vanilla`, `get-vanilla-query-order-key-case`,
`post-x-www-form-urlencoded`) and the `ListUsers` example of the IAM documentation."""

import datetime
import unittest

from lazaret.scanner import sigv4

ACCESS = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
NOW = datetime.datetime(2015, 8, 30, 12, 36, 0, tzinfo=datetime.timezone.utc)


def authorization(method, query=None, body=None, headers=None, host="example.amazonaws.com", service="service", now=NOW):
    out = sigv4.sign(method, host, "/", query or {}, body, headers or {}, ACCESS, SECRET, "us-east-1", service, now)
    return out["authorization"]


def signed(headers, signature, service="service"):
    return (f"AWS4-HMAC-SHA256 Credential={ACCESS}/20150830/us-east-1/{service}/aws4_request, SignedHeaders={headers}, "
            f"Signature={signature}")


class PublishedVectorTests(unittest.TestCase):
    def test_the_signing_key_of_the_documentation(self):
        key = sigv4.signing_key(SECRET, "20150830", "us-east-1", "iam")
        self.assertEqual(key.hex(), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")

    def test_get_vanilla(self):
        self.assertEqual(authorization("GET"), signed("host;x-amz-date", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"))

    def test_post_vanilla(self):
        self.assertEqual(authorization("POST"), signed("host;x-amz-date", "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"))

    def test_the_query_is_sorted(self):
        self.assertEqual(authorization("GET", {"Param2": "value2", "Param1": "value1"}),
                         signed("host;x-amz-date", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"))

    def test_a_form_body_and_its_content_type(self):
        got = authorization("POST", body=b"Param1=value1", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(got, signed("content-type;host;x-amz-date", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"))

    def test_the_iam_list_users_example(self):
        got = authorization("GET", {"Action": "ListUsers", "Version": "2010-05-08"}, host="iam.amazonaws.com", service="iam",
                            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
        self.assertEqual(got, signed("content-type;host;x-amz-date", "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", "iam"))


class BehaviourTests(unittest.TestCase):
    def test_the_headers_come_back_with_a_date_and_an_authorization_and_the_given_ones_are_not_changed(self):
        given = {"Content-Type": "text/plain"}
        out = sigv4.sign("GET", "h.example", "/", {}, None, given, ACCESS, SECRET, "us-east-1", "sts", NOW)
        self.assertEqual(given, {"Content-Type": "text/plain"})
        self.assertEqual(out["Content-Type"], "text/plain")
        self.assertEqual(out["x-amz-date"], "20150830T123600Z")
        self.assertTrue(out["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, "))
        self.assertNotIn("host", {k.lower() for k in out})                   # (the transport sends it, and it must be its own)

    def test_what_is_signed_is_the_request(self):
        base = authorization("POST", body=b"a=1")
        self.assertNotEqual(base, authorization("POST", body=b"a=2"))
        self.assertNotEqual(base, authorization("GET", body=b"a=1"))
        self.assertNotEqual(base, authorization("POST", body=b"a=1", host="other.amazonaws.com"))
        self.assertNotEqual(base, authorization("POST", body=b"a=1", service="sts"))
        self.assertNotEqual(base, authorization("POST", body=b"a=1", now=NOW + datetime.timedelta(seconds=1)))
        self.assertNotEqual(base, authorization("POST", {"x": "1"}, body=b"a=1"))
        self.assertNotEqual(base, authorization("POST", body=b"a=1", headers={"X-Extra": "1"}))

    def test_a_header_is_signed_as_its_trimmed_value_in_lower_case(self):
        a = authorization("GET", headers={"X-Extra": "  a   b  "})
        b = authorization("GET", headers={"x-extra": "a b"})
        self.assertEqual(a, b)

    def test_a_query_is_encoded_before_it_is_sorted_in_signing(self):
        a = authorization("GET", {"a b": "x/y", "c": "é"})
        b = authorization("GET", {"c": "é", "a b": "x/y"})
        self.assertEqual(a, b)
        self.assertNotEqual(a, authorization("GET", {"a b": "x y", "c": "é"}))

    def test_a_time_with_a_zone_is_taken_as_utc(self):
        zone = datetime.timezone(datetime.timedelta(hours=-5))
        local = NOW.astimezone(zone)
        self.assertEqual(authorization("GET", now=local), authorization("GET"))
        self.assertEqual(sigv4.sign("GET", "h.example", "/", {}, None, {}, ACCESS, SECRET, "r", "s", local)["x-amz-date"], "20150830T123600Z")

    def test_a_time_with_no_zone_is_taken_as_it_is(self):
        naive = datetime.datetime(2015, 8, 30, 12, 36, 0)
        self.assertEqual(authorization("GET", now=naive), authorization("GET"))


if __name__ == "__main__":
    unittest.main()
