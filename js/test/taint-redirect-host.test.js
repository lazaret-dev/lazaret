// Q-5 (0.1.9): a check of the parsed URL's host against a collection guards an
// open redirect (urlparse(u).netloc in ALLOWED, p.netloc for p = urlparse(u),
// h for h = urlparse(u).netloc; `not in` with a block that leaves); a substring
// test does not. Twin of python/tests/scanner/test_taint_redirect_host.py: the
// pass is the native engine's in both packages (its helpers are held by
// rust/crates/lazaret-engine/src/taint_tests.rs). Nothing here runs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { taintScan } from "../src/scanner/scan.js";

const FLASK = "from flask import Flask, request, redirect, abort\nfrom urllib.parse import urlparse, urlsplit\n"
  + "import urllib.parse, os\napp = Flask(__name__)\nALLOWED = {'example.invalid', 'www.example.invalid'}\n";
const VIEW = FLASK + "@app.route('/go')\ndef go():\n    url = request.args.get('next', '')\n";
const found = (src) => new Set(taintScan("x.py", src.split("\n"), "py")
  .filter((i) => i.rule.startsWith("T-")).map((i) => `${i.rule}:${i.line}`));

test("a check of the parsed URL's host guards the redirect", () => {
  const quiet = [
    VIEW + "    if urlparse(url).netloc in ALLOWED:\n        return redirect(url)\n    return 'no'\n",
    VIEW + "    if urllib.parse.urlparse(url).hostname not in ['example.invalid']:\n        abort(400)\n"
      + "    return redirect(url)\n",
    VIEW + "    try:\n        parsed = urlparse(url)\n"
      + "        if parsed.netloc not in ['example.invalid', ''] or parsed.scheme not in ('http', 'https', ''):\n"
      + "            return 'refused', 400\n    except ValueError:\n        return 'bad', 400\n    return redirect(url)\n",
    VIEW + "    host = urlsplit(url).hostname\n    if host not in ALLOWED: return 'refused', 400\n    return redirect(url)\n",
    VIEW + "    if urlparse(url).netloc not in ALLOWED:\n        abort(400)\n    else:\n        return redirect(url)\n",
  ];
  for (const src of quiet) assert.deepEqual(found(src), new Set(), src.slice(FLASK.length));
});

test("a substring test, or the branch the check does not guard, is reported", () => {
  const reported = [
    [VIEW + "    return redirect(url)\n", ["T-REDIR:9"]],
    [VIEW + "    if 'example.invalid' in url:\n        return redirect(url)\n", ["T-REDIR:10"]],
    [VIEW + "    if url.startswith('https://example.invalid'):\n        return redirect(url)\n", ["T-REDIR:10"]],
    [VIEW + "    if urlparse(url).netloc in 'www.example.invalid':\n        return redirect(url)\n", ["T-REDIR:10"]],
    [VIEW + "    if urlparse(url).netloc in ALLOWED:\n        pass\n    else:\n        return redirect(url)\n", ["T-REDIR:12"]],
    [VIEW + "    if urlparse(url).netloc not in ALLOWED:\n        return redirect(url)\n    return 'ok'\n", ["T-REDIR:10"]],
    [VIEW + "    if urlparse(url).netloc in ALLOWED or url.startswith('/'):\n        return redirect(url)\n", ["T-REDIR:10"]],
    [VIEW + "    if urlparse(url).netloc in ALLOWED:\n        os.system('curl ' + url)\n        return redirect(url)\n",
      ["T-CMD:10"]],
  ];
  for (const [src, want] of reported) assert.deepEqual(found(src), new Set(want), src.slice(FLASK.length));
});
