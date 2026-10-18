"""RA-6 package wiring. All archive members are inert, invented source text."""
import json
import unittest
from tests.registry.test_package_code import go, rust, scan, crate_tgz
REASON = "deletes the user's files"

class DeletionPackageTests(unittest.TestCase):
    def check(self, result, rule, severity):
        issues = [i for i in result['issues'] if i['rule']==rule and REASON in i['msg']]
        self.assertTrue(issues, result['issues'])
        self.assertTrue(all(i['sev']==severity for i in issues), issues)

    def test_go_moments(self):
        for fn, rule, sev in [('init','SC-IMPORT-RISK','CRITICAL'),('Clean','SC-USE-RISK','MAJOR')]:
            with self.subTest(fn=fn):
                self.check(go({'p.go':f'package p\nimport "os"\nfunc {fn}(){{os.RemoveAll("/home/example")}}\n'}),rule,sev)

    def test_rust_moments(self):
        self.check(rust({'build.rs':'fn main(){std::fs::remove_dir_all("/home/example").unwrap();}',
                         'src/lib.rs':'pub fn f(){}'}),'SC-INSTALL-HOOK','CRITICAL')
        self.check(rust({'src/lib.rs':'pub fn clean(){std::fs::remove_dir_all("/home/example").unwrap();}'}),'SC-USE-RISK','MAJOR')

    def test_npm_moments(self):
        src='const fs=require("fs");fs.rmSync("/home/example",{recursive:true});'
        for scripts,rule,sev in [({'postinstall':'node clean.js'},'SC-INSTALL-HOOK','CRITICAL'),({},'SC-USE-RISK','MAJOR')]:
            with self.subTest(scripts=scripts):
                files={'package.json':json.dumps({'name':'example','version':'1.0.0','main':'index.js','scripts':scripts}),
                       'index.js':'module.exports={};','clean.js':src}
                self.check(scan(crate_tgz(files,root='package'),'tgz','npm'),rule,sev)

    def test_python_moments(self):
        src='import shutil\nshutil.rmtree("/home/example")\n'
        for path,rule,sev in [('setup.py','SC-INSTALL-HOOK','CRITICAL'),('ra6pkg/__init__.py','SC-IMPORT-RISK','CRITICAL'),('ra6pkg/clean.py','SC-USE-RISK','MAJOR')]:
            with self.subTest(path=path):
                files={'PKG-INFO':'Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n',
                       'setup.py':'from setuptools import setup\nsetup(name="example",version="1.0.0",packages=["ra6pkg"])\n',
                       'ra6pkg/__init__.py':'',path:src}
                self.check(scan(crate_tgz(files,root='example-1.0.0'),'tgz','sdist'),rule,sev)
