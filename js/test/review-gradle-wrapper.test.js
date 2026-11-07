// FP-GRADLE-WRAPPER: a Gradle wrapper jar is judged by its checksum against Gradle's published wrapper checksums, with
// the gradle-wrapper.properties beside it, in the npm package's project scan and --deps, as the Python package judges
// it (python/tests/scanner/test_review_gradle_wrapper.py; the engine's gradle/, through collect_file and its
// {"read": "sibling"} need). Genuine jars from tests/fixtures/gradle-wrapper; the changed ones are made here. Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/index.js";

const FIX = fileURLToPath(new URL("../../tests/fixtures/gradle-wrapper/", import.meta.url));
const PACK = fileURLToPath(new URL("../../rust/crates/lazaret-engine/rules/lazaret-rules.json", import.meta.url));
/** The next major's first release: may be newer than the pack's list of Gradle's checksums (its newest major + 1). */
const NEXT = `${Math.max(...Object.keys(JSON.parse(readFileSync(PACK, "utf8")).values.GRADLE_WRAPPER_CHECKSUMS.map)
  .map((v) => Number(v.split(".")[0]))) + 1}.0`;
const JAR = "gradle/wrapper/gradle-wrapper.jar", PROPS = "gradle/wrapper/gradle-wrapper.properties";
const genuine = (v) => readFileSync(join(FIX, v, JAR));
const props = (v) => "distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n"
  + `distributionUrl=https\\://services.gradle.org/distributions/gradle-${v}-bin.zip\n`
  + "zipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n";
function oneByte(jar) {
  const out = Buffer.from(jar);
  out[out.length >> 1] ^= 1;
  return out;
}

function scan(files, extra = []) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-gradle-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const p = join(d, ...rel.split("/"));
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    }
    run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: () => {} });
    return JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const found = (issues) => issues.filter((i) => i.rule.startsWith("SC-"))
  .map((i) => [i.file.replaceAll("\\", "/"), i.rule, i.sev]).sort();

test("genuine wrappers are quiet", () => {
  for (const [v, dist] of [["4.10.3", "4.10.3"], ["8.14", "9.4.1"], ["9.8", "9.8.1"]]) {
    assert.deepEqual(found(scan({ [JAR]: genuine(v), [PROPS]: props(dist), "build.gradle": "plugins { id 'java' }\n" })), [], v);
  }
});

test("a changed wrapper is critical; one for a Gradle newer than the list can't be verified", () => {
  const jar = oneByte(genuine("9.8"));
  assert.deepEqual(found(scan({ [JAR]: jar, [PROPS]: props("9.8.1") })), [[JAR, "SC-GRADLE-WRAPPER", "CRITICAL"]]);
  assert.deepEqual(found(scan({ [JAR]: jar })), [[JAR, "SC-GRADLE-WRAPPER", "CRITICAL"]]);
  const issues = scan({ [JAR]: jar, [PROPS]: props(NEXT) });
  assert.deepEqual(found(issues), [[JAR, "SC-GRADLE-WRAPPER", "MAJOR"]]);
  assert.ok(issues.find((i) => i.rule === "SC-GRADLE-WRAPPER").msg.includes("newer than Lazaret's list of Gradle's checksums"));
  // (the review of Oct 27) a version no next release has is a changed wrapper's, and so is the first of two URLs
  assert.deepEqual(found(scan({ [JAR]: jar, [PROPS]: props("99.0.0") })), [[JAR, "SC-GRADLE-WRAPPER", "CRITICAL"]]);
  assert.deepEqual(found(scan({ [JAR]: jar, [PROPS]: props(NEXT) + props("9.8.1") })), [[JAR, "SC-GRADLE-WRAPPER", "CRITICAL"]]);
});

test("a genuine wrapper's distribution over plain HTTP, or from another host", () => {
  const http = props("8.14").replace("https\\://services.gradle.org", "http\\://192.0.2.1");
  const mirror = props("8.14").replace("services.gradle.org", "repo.example.invalid");
  assert.deepEqual(found(scan({ [JAR]: genuine("8.14"), [PROPS]: http })), [[JAR, "SC-GRADLE-WRAPPER", "MAJOR"]]);
  assert.deepEqual(found(scan({ [JAR]: genuine("8.14"), [PROPS]: mirror })), [[JAR, "SC-GRADLE-WRAPPER", "INFO"]]);
});

test("the distribution Java reads (the re-review of Oct 27, N3)", () => {
  // an escaped key and a continuation across a CRLF hide no plain-HTTP URL; past the bytes read: can't be verified
  const https = "https\\://services.gradle.org/distributions/gradle-8.14-bin.zip", http = "http\\://192.0.2.1/gradle-8.14-bin.zip";
  for (const p of [`distributionUrl=${https}\n\\u0064istributionUrl=${http}\n`,
    `distributionUrl=${http}\r\nzipStorePath=wrapper/dists\\\r\ndistributionUrl=${https}\r\n`]) {
    const issues = scan({ [JAR]: genuine("8.14"), [PROPS]: p });
    assert.deepEqual(found(issues), [[JAR, "SC-GRADLE-WRAPPER", "MAJOR"]], JSON.stringify(p));
    assert.ok(issues.find((i) => i.rule === "SC-GRADLE-WRAPPER").msg.includes("plain HTTP"));
  }
  const head = `distributionUrl=${https}\n`;
  const issues = scan({ [JAR]: genuine("8.14"), [PROPS]: head + "#".repeat(65536 - head.length) + `\ndistributionUrl=${http}\n` });
  assert.deepEqual(found(issues), [[JAR, "SC-GRADLE-WRAPPER", "MAJOR"]]);
  assert.ok(issues.find((i) => i.rule === "SC-GRADLE-WRAPPER").msg.includes("longer than the 65536 bytes"));
  assert.deepEqual(found(scan({ [JAR]: genuine("8.14"), [PROPS]: head + "#".repeat(65536 - head.length) })), []);
});

test("elsewhere or under another name, a jar as any", () => {
  const jar = oneByte(genuine("9.8"));
  assert.deepEqual(found(scan({ "libs/gradle-wrapper.jar": jar, "gradle/wrapper/other.jar": jar })),
    [["gradle/wrapper/other.jar", "SC-BINARY", "MAJOR"], ["libs/gradle-wrapper.jar", "SC-BINARY", "MAJOR"]]);
});

test("over the size limit: can't be verified", () => {
  assert.deepEqual(found(scan({ [JAR]: genuine("9.8"), [PROPS]: props("9.8.1") }, ["--max-source-bytes", "4096"])),
    [[JAR, "SC-GRADLE-WRAPPER", "MAJOR"]]);
});

test("--deps: a dependency's Android wrapper", () => {
  const base = { "app.js": "require('rnlib')\n", "package.json": '{"dependencies": {"rnlib": "1.0.0"}}',
    "node_modules/rnlib/package.json": '{"name": "rnlib", "version": "1.0.0"}', "node_modules/rnlib/index.js": "module.exports = 1\n",
    [`node_modules/rnlib/android/${PROPS}`]: props("8.14") };
  assert.deepEqual(found(scan({ ...base, [`node_modules/rnlib/android/${JAR}`]: genuine("8.14") }, ["--deps"])), []);
  assert.deepEqual(found(scan({ ...base, [`node_modules/rnlib/android/${JAR}`]: oneByte(genuine("8.14")) }, ["--deps"])),
    [[`node_modules/rnlib/android/${JAR}`, "SC-GRADLE-WRAPPER", "CRITICAL"]]);
});
