"""Attack documents shared by the safexml tests. Inert: parsing them is the
attack, and every test expects lazaret.safexml to refuse them."""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

QUADRATIC = b'<!DOCTYPE r [<!ENTITY a "' + b"A" * 50_000 + b'">]><r>' + b"&a;" * 5_000 + b"</r>"
XXE_FILE = b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
XXE_PARAMETER = b'<!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><r/>'
UNPARSED = b'<!DOCTYPE r [<!NOTATION n SYSTEM "viewer"><!ENTITY u SYSTEM "img.gif" NDATA n>]><r/>'
INTERNAL_ENTITY = b'<!DOCTYPE r [<!ENTITY name "Lazaret">]><r>&name;</r>'
DOCTYPE_ONLY = b"<!DOCTYPE r><r/>"

ENTITY_ATTACKS = {
    "billion-laughs": BILLION_LAUGHS, "quadratic": QUADRATIC, "xxe-file": XXE_FILE,
    "xxe-parameter": XXE_PARAMETER, "unparsed": UNPARSED, "internal": INTERNAL_ENTITY,
}


def external_reference_docs(url):
    """Documents that would make a careless parser fetch from `url`."""
    return {
        "external-dtd": f'<!DOCTYPE r SYSTEM "{url}/evil.dtd"><r/>'.encode(),
        "external-dtd-public": f'<!DOCTYPE r PUBLIC "-//X//Y//EN" "{url}/evil.dtd"><r/>'.encode(),
        "external-entity": f'<!DOCTYPE r [<!ENTITY x SYSTEM "{url}/secret">]><r>&x;</r>'.encode(),
        "external-parameter": f'<!DOCTYPE r [<!ENTITY % p SYSTEM "{url}/evil.dtd"> %p;]><r/>'.encode(),
    }
