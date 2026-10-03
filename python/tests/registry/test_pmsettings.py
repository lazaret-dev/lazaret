"""lazaret.registry.pmsettings (0.1.8): where each package manager fetches a
package from, and the credentials its own settings give for that place —
read the way each tool reads them, and matched to hosts the way npm (a path
and what is under it) and pip / uv (a whole host) match them. The
credentials are fake and built here."""

import base64
import os
import stat
import sys
import tempfile
import unittest

from lazaret.registry import pmsettings as pm

TOKEN = "npm_" + "Abc123" * 6                  # (built in pieces: a whole one would trip secret scanners)
PASSWORD = "p4ss" + "-" + "w0rd"


def b64(text):
    return base64.b64encode(text.encode()).decode()


class CredentialsTests(unittest.TestCase):
    def test_npm_keys_cover_a_path_and_what_is_under_it(self):
        c = pm.Credentials()
        c.token("//reg.example/npm/", TOKEN)
        c.token("//reg.example/npm/private/", "other")
        self.assertEqual(c.header("https://reg.example/npm/left-pad"), "Bearer " + TOKEN)
        self.assertEqual(c.header("https://reg.example/npm/left-pad/-/left-pad-1.3.0.tgz"), "Bearer " + TOKEN)
        self.assertEqual(c.header("https://reg.example/npm/private/x/-/x-1.0.0.tgz"), "Bearer other")
        for url in ("https://reg.example/other/x", "https://reg.example/npmx/y", "https://reg.example/",
                    "https://evil.example/npm/left-pad", "https://reg.example:8443/npm/left-pad"):
            with self.subTest(url):
                self.assertIsNone(c.header(url))
        c.token("//reg.example/scoped", "no-slash")          # npm reads //host/scoped as //host/scoped/
        self.assertEqual(c.header("https://reg.example/scoped/x"), "Bearer no-slash")

    def test_the_first_added_wins_and_ports_are_part_of_the_host(self):
        c = pm.Credentials()
        c.token("//reg.example:8443/", "first")
        c.token("https://reg.example:8443/", "second")
        c.token("https://reg.example:443/", "default-port")
        self.assertEqual(c.header("https://reg.example:8443/a"), "Bearer first")
        self.assertEqual(c.header("https://reg.example/a"), "Bearer default-port")

    def test_plain_http_only_to_this_machine(self):
        c = pm.Credentials()
        c.login("http://reg.example/simple/", "u", PASSWORD, whole_host=True)
        c.login("http://127.0.0.1:4873/", "u", PASSWORD)
        self.assertIsNone(c.header("http://reg.example/simple/x/"))
        self.assertTrue(c.withheld("http://reg.example/packages/x.whl"))
        self.assertEqual(c.header("http://127.0.0.1:4873/x"), pm.basic("u", PASSWORD))
        self.assertFalse(c.withheld("https://other.example/"))

    def test_a_python_index_covers_its_whole_host(self):
        c = pm.Credentials()
        c.login("https://pkgs.example/org/simple/", "u", PASSWORD, whole_host=True)
        self.assertEqual(c.header("https://pkgs.example/org/packages/x-1.0.whl"), pm.basic("u", PASSWORD))

    def test_userinfo_is_taken_out_of_urls(self):
        self.assertEqual(pm.split_userinfo("https://u:p%40ss@h.example:8443/simple/"),
                         ("https://h.example:8443/simple/", ("u", "p@ss")))
        self.assertEqual(pm.split_userinfo("https://h.example/x"), ("https://h.example/x", None))
        self.assertEqual(pm.shown("https://token@h.example/x"), "https://h.example/x")


class NpmrcTests(unittest.TestCase):
    def test_env_replace_is_npms(self):
        env = {"TOKEN": TOKEN}
        self.assertEqual(pm.env_replace("${TOKEN}", env), TOKEN)
        self.assertEqual(pm.env_replace("${MISSING}", env), "${MISSING}")          # npm refuses it then
        self.assertEqual(pm.env_replace("${MISSING?}", env), "")
        self.assertEqual(pm.env_replace("\\${TOKEN}", env), "${TOKEN}")            # escaped
        self.assertEqual(pm.env_replace("\\\\${TOKEN}", env), "\\" + TOKEN)

    def test_parse(self):
        text = ("; a comment\n# another\nregistry = https://reg.example/npm/\n"
                "//reg.example/npm/:_authToken=${TOKEN}\n@corp:registry=\"https://corp.example/\"\n"
                "[section]\nignored=1\nnot a setting\n")
        self.assertEqual(pm.parse_npmrc(text, {"TOKEN": TOKEN}),
                         {"registry": "https://reg.example/npm/", "//reg.example/npm/:_authToken": TOKEN,
                          "@corp:registry": "https://corp.example/"})

    def test_environment_settings(self):
        env = {"npm_config_registry": "https://reg.example/", "NPM_CONFIG_//reg.example/:_authToken": TOKEN,
               "npm_config_strict_ssl": "false", "npm_config_empty": "", "OTHER": "x"}
        self.assertEqual(pm.npm_env_settings(env), {"registry": "https://reg.example/",
                                                    "//reg.example/:_authToken": TOKEN, "strict-ssl": "false"})

    def test_credentials_of_the_keys(self):
        settings = {"//a.example/:_authToken": TOKEN, "//b.example/npm/:_auth": b64("u:" + PASSWORD),
                    "//c.example/:username": "u", "//c.example/:_password": b64(PASSWORD),
                    "//d.example/:_authToken": TOKEN, "//d.example/:_auth": b64("ignored:x"),
                    "_authToken": "legacy"}
        c = pm.npm_credentials(settings, "https://default.example/")
        self.assertEqual(c.header("https://a.example/x"), "Bearer " + TOKEN)
        self.assertEqual(c.header("https://b.example/npm/x"), "Basic " + b64("u:" + PASSWORD))
        self.assertEqual(c.header("https://c.example/x"), pm.basic("u", PASSWORD))
        self.assertEqual(c.header("https://d.example/x"), "Bearer " + TOKEN)          # a token first
        self.assertEqual(c.header("https://default.example/x"), "Bearer legacy")      # unscoped: the default's

    def test_registries_and_a_registry_url_with_credentials(self):
        s = pm.NpmSettings({"registry": "https://u:" + PASSWORD + "@reg.example/npm",
                            "@corp:registry": "https://corp.example/", "//corp.example/:_authToken": TOKEN})
        self.assertEqual(s.default, "https://reg.example/npm/")
        self.assertEqual(s.scoped, {"@corp": "https://corp.example/"})
        self.assertEqual(s.creds.header("https://reg.example/npm/x"), pm.basic("u", PASSWORD))
        self.assertEqual(s.creds.header("https://corp.example/@corp/x"), "Bearer " + TOKEN)

    def test_npm_reads_its_files_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            project, home = os.path.join(d, "p"), os.path.join(d, "home")
            os.makedirs(project)
            os.makedirs(home)
            with open(os.path.join(project, ".npmrc"), "w", encoding="utf-8") as f:
                f.write("//reg.example/:_authToken=project\n")
            with open(os.path.join(home, ".npmrc"), "w", encoding="utf-8") as f:
                f.write("//reg.example/:_authToken=user\n//other.example/:_authToken=user\n")
            env = {"HOME": home}
            paths = pm.npmrc_paths(env, [project])
            self.assertEqual(paths, [os.path.join(project, ".npmrc"), os.path.join(home, ".npmrc")])
            got = pm.npmrc_settings(paths, env)
            self.assertEqual(got["//reg.example/:_authToken"], "project")
            self.assertEqual(got["//other.example/:_authToken"], "user")


class YarnAndBunTests(unittest.TestCase):
    def test_yarn_berry(self):
        values = {"npmRegistryServer": "https://reg.example/", "npmAuthToken": "top",
                  "npmScopes": {"corp": {"npmRegistryServer": "https://corp.example/npm", "npmAuthToken": TOKEN},
                                "open": {"npmRegistryServer": None, "npmAuthToken": None}},
                  "npmRegistries": {"//mirror.example/npm": {"npmAuthIdent": "u:" + PASSWORD},
                                    "https://reg.example": {"npmAuthToken": "registry-own"}},
                  "npmAuthIdent": None}
        settings, creds = pm.berry_settings("yarn", {}, ".", get=values.get)
        self.assertEqual(settings, {"registry": "https://reg.example/", "@corp:registry": "https://corp.example/npm/",
                                    "@open:registry": "https://reg.example/"})
        self.assertEqual(creds.header("https://corp.example/npm/@corp/x"), "Bearer " + TOKEN)
        self.assertEqual(creds.header("https://mirror.example/npm/x"), "Basic " + b64("u:" + PASSWORD))
        self.assertEqual(creds.header("https://reg.example/x"), "Bearer registry-own")   # its own over the top one

    def test_bun(self):
        with tempfile.TemporaryDirectory() as d:
            project, home = os.path.join(d, "p"), os.path.join(d, "home")
            os.makedirs(project)
            os.makedirs(home)
            with open(os.path.join(project, "bunfig.toml"), "w", encoding="utf-8") as f:
                f.write('[install]\nregistry = { url = "https://reg.example/", token = "$BUN_TOKEN" }\n'
                        '[install.scopes]\ncorp = "https://u:' + PASSWORD + '@corp.example/"\n'
                        '"@team" = { url = "https://team.example/", username = "t", password = "${TEAM_PW}" }\n')
            with open(os.path.join(home, ".bunfig.toml"), "w", encoding="utf-8") as f:
                f.write('[install]\nregistry = "https://ignored.example/"\n')
            with open(os.path.join(project, ".npmrc"), "w", encoding="utf-8") as f:
                f.write("@npmrc:registry=https://npmrc.example/\n//npmrc.example/:_authToken=from-npmrc\n")
            settings, creds = pm.bun_settings({"HOME": home, "BUN_TOKEN": TOKEN, "TEAM_PW": PASSWORD}, project)
            self.assertEqual(settings["registry"], "https://reg.example/")
            self.assertEqual(settings["@corp:registry"], "https://corp.example/")
            self.assertEqual(settings["@team:registry"], "https://team.example/")
            self.assertEqual(settings["@npmrc:registry"], "https://npmrc.example/")
            self.assertEqual(creds.header("https://reg.example/x"), "Bearer " + TOKEN)
            self.assertEqual(creds.header("https://corp.example/@corp/x"), pm.basic("u", PASSWORD))
            self.assertEqual(creds.header("https://team.example/@team/x"), pm.basic("t", PASSWORD))
            npm = pm.NpmSettings(settings, creds=creds)                  # .npmrc's keys come along
            self.assertEqual(npm.creds.header("https://npmrc.example/x"), "Bearer from-npmrc")


class PythonIndexTests(unittest.TestCase):
    def test_pip(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "pip")
            with open(fake, "w", encoding="utf-8") as f:           # prints what `pip config list` prints
                f.write(f"#!{sys.executable}\nprint(\":env:.config-file='/x'\")\n"
                        "print(\"global.index-url='https://global.example/simple/'\")\n"
                        "print(\"install.index-url='https://install.example/simple/'\")\n"
                        "print(\"global.extra-index-url='https://a.example/simple/\\\\nhttps://b.example/simple/'\")\n")
            os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
            if os.name == "nt":
                self.skipTest("a fake pip is a POSIX script")
            got = pm.pip_indexes(fake, {}, d)
            self.assertEqual([(i.url, i.default) for i in got],
                             [("https://install.example/simple/", True), ("https://a.example/simple/", False),
                              ("https://b.example/simple/", False)])
            got = pm.pip_indexes(fake, {"PIP_INDEX_URL": "https://env.example/simple",
                                        "PIP_EXTRA_INDEX_URL": "https://c.example/simple"}, d)
            self.assertEqual([i.url for i in got], ["https://env.example/simple/", "https://c.example/simple/"])

    def test_uv(self):
        with tempfile.TemporaryDirectory() as d:
            project, xdg = os.path.join(d, "p", "sub"), os.path.join(d, "xdg")
            os.makedirs(project)
            os.makedirs(os.path.join(xdg, "uv"))
            with open(os.path.join(d, "p", "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write('[project]\nname = "p"\n[[tool.uv.index]]\nname = "corp"\nurl = "https://corp.example/simple"\n'
                        '[[tool.uv.index]]\nname = "pinned"\nurl = "https://pinned.example/simple"\nexplicit = true\n'
                        '[[tool.uv.index]]\nname = "mirror"\nurl = "https://mirror.example/simple"\ndefault = true\n'
                        '[tool.uv.pip]\nextra-index-url = ["https://pip-only.example/simple"]\n')
            with open(os.path.join(xdg, "uv", "uv.toml"), "w", encoding="utf-8") as f:
                f.write('index-strategy = "unsafe-best-match"\n[[index]]\nurl = "https://user.example/simple"\n')
            env = {"XDG_CONFIG_HOME": xdg, "XDG_CONFIG_DIRS": os.path.join(d, "none"),
                   "UV_INDEX": "env=https://env.example/simple https://env2.example/simple"}
            got = pm.uv_indexes(env, project)
            self.assertEqual([(i.url, i.name, i.default) for i in got], [
                ("https://env.example/simple/", "env", False), ("https://env2.example/simple/", None, False),
                ("https://corp.example/simple/", "corp", False), ("https://user.example/simple/", None, False),
                ("https://mirror.example/simple/", "mirror", True)])
            self.assertIn("https://pip-only.example/simple/", [i.url for i in pm.uv_indexes(env, project, pip=True)])
            self.assertEqual(pm.uv_index_strategy(env, project), "unsafe-best-match")
            env["UV_DEFAULT_INDEX"] = "https://default.example/simple"
            self.assertEqual(pm.uv_indexes(env, project)[-1].url, "https://default.example/simple/")
            self.assertEqual([i.url for i in pm.uv_indexes(dict(env, UV_NO_CONFIG="1"), project)],
                             ["https://env.example/simple/", "https://env2.example/simple/",
                              "https://default.example/simple/"])

    def test_index_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            netrc = os.path.join(d, "netrc")
            with open(netrc, "w", encoding="utf-8") as f:
                f.write(f"machine files.example login nu password {PASSWORD}\n")
            os.chmod(netrc, 0o600)
            indexes = [pm.Index("https://u:" + PASSWORD + "@a.example/simple/"),
                       pm.Index("https://b.example/simple/", name="corp-idx")]
            env = {"NETRC": netrc, "UV_INDEX_CORP_IDX_USERNAME": "cu", "UV_INDEX_CORP_IDX_PASSWORD": PASSWORD}
            creds = pm.index_credentials(indexes, env, hosts=["https://files.example/x.whl"])
            self.assertEqual(indexes[0].url, "https://a.example/simple/")          # taken out of the URL
            self.assertEqual(creds.header("https://a.example/packages/x.whl"), pm.basic("u", PASSWORD))
            self.assertEqual(creds.header("https://b.example/simple/x/"), pm.basic("cu", PASSWORD))
            self.assertEqual(creds.header("https://files.example/x.whl"), pm.basic("nu", PASSWORD))
            self.assertIsNone(creds.header("https://c.example/"))


if __name__ == "__main__":
    unittest.main()
