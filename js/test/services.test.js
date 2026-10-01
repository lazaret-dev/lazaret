// Programs set to start at login or boot (0.1.8): twin of
// python/tests/scanner/test_persistence_services.py. The install-script test
// fails on a systemd unit written or enabled, a launchd agent written or
// loaded, a cron job installed, a Windows Run key written, a scheduled task
// created, the Startup folder written and an XDG autostart entry; import-time
// code never gets these. tests/architecture/test_js_parity_hooks.py compares
// the engines on a random corpus. Inert text only: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { serviceReasons, installScriptRisk, importTimeRisk } from "../src/lib/hooks.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "lazaret.js");
const UNIT_WRITER = "const { execSync } = require('child_process');\nconst fs = require('fs');\nconst os = require('os');\n"
  + "const path = require('path');\nconst dir = path.join(os.homedir(), '.config', 'systemd', 'user');\n"
  + "fs.mkdirSync(dir, { recursive: true });\n"
  + "fs.writeFileSync(path.join(dir, 'pgmon.service'), ['[Unit]', '[Service]', `ExecStart=/usr/bin/python3 ${p}`,\n"
  + "  'Restart=always', '[Install]', 'WantedBy=default.target'].join('\\n'));\n"
  + "execSync('systemctl --user daemon-reload');\nexecSync('systemctl --user enable pgmon.service');\n";

const each = (cases, want) => {
  for (const text of cases) assert.deepEqual(serviceReasons(text), want, text.slice(0, 60));
};

test("systemd units and launchd agents", () => {
  each([UNIT_WRITER, "cp x.service ~/.config/systemd/user/ && systemctl --user daemon-reload",
    "node setup.js && systemctl --user enable --now agent.service",
    "subprocess.run(['systemctl', '--user', 'enable', 'x.service'])",
    "echo \"$UNIT\" | sudo tee /etc/systemd/system/x.service"], ["installs a systemd service"]);
  each(["if (fs.existsSync('/run/systemd/system')) fs.writeFileSync(p, s)",
    "console.log('Run: sudo systemctl enable myapp')", "execSync('systemctl is-enabled docker')",
    "var a=1;" + "x=>y;".repeat(300) + "fs.existsSync('/etc/systemd/system')&&fs.writeFileSync(o,d)"], []);
  each(["const p = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.x.plist');\n"
    + "fs.writeFileSync(p, `<key>RunAtLoad</key><true/><key>ProgramArguments</key>`);\n",
    "cp com.x.plist ~/Library/LaunchAgents/", "execSync(`launchctl load -w ${plist}`)"], ["installs a launchd agent or daemon"]);
  each(["const agents = fs.readdirSync(path.join(home, 'Library', 'LaunchAgents'));\nfs.writeFileSync(out, x);\n",
    "execSync('launchctl list')"], []);
});

test("cron jobs, Run keys and scheduled tasks", () => {
  each(["os.system('(crontab -l 2>/dev/null; echo \"@reboot python3 ~/.x/a.py\") | crontab -')",
    "subprocess.run(['crontab', tmp])", "os.system('crontab /tmp/cr')",
    "from crontab import CronTab\ncron = CronTab(user=True)\ncron.write()\n",
    "with open('/etc/cron.d/updater', 'w') as f:\n    f.write(line)\n"], ["adds a cron job"]);
  each(["execSync('crontab -l')", "subprocess.run(['crontab', '-l'])", "x = 'a|cron|crontab|csplit|curl'; exec(x)"], []);
  each(["k = winreg.OpenKey(HKCU, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE)\n"
    + "winreg.SetValueEx(k, 'Updater', 0, winreg.REG_SZ, exe)\n",
    "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x -Value $p",
    "spawn('reg', ['add', 'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce', '/v', 'x'])"],
  ["adds a program to a Windows Run key"]);
  each(["winreg.QueryValueEx(winreg.OpenKey(HKCU, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'), 'x')",
    "# r['HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Run']['Example 1'] = 'x'\n"
    + "#\n".repeat(300) + "win32.RegSetValueEx(h, n, v)"], []);
  // the span is counted in code points: an emoji is one, not two UTF-16 units
  assert.deepEqual(serviceReasons("CurrentVersion\\Run" + "\u{1F600}".repeat(394) + "REG_SZ"), ["adds a program to a Windows Run key"]);
  assert.deepEqual(serviceReasons("CurrentVersion\\Run" + "\u{1F600}".repeat(395) + "REG_SZ"), []);
  each(["execSync(`schtasks /create /tn Updater /tr \"${exe}\" /sc onlogon /f`)",
    "@echo off\nSCHTASKS.EXE /CREATE /SC ONSTART /TN x /TR c:\\x.exe\n",
    "Register-ScheduledTask -TaskName x -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Action $a",
    "var s = new ActiveXObject('Schedule.Service'); f.RegisterTaskDefinition('x', d, 6)"], ["creates a Windows scheduled task"]);
  each(["execSync('schtasks /query /fo csv')", '"ecs:RegisterTaskDefinition",'], []);
});

test("the Startup folder and desktop autostart", () => {
  each(["p = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')\nshutil.copy(exe, p)\n",
    "s = shell.CreateShortcut(os.path.join(winshell.startup(), 'x.lnk'))\ns.Save()\n"], ["puts a program in the Windows Startup folder"]);
  each(["const f = path.join(os.homedir(), '.config', 'autostart', 'x.desktop');\nfs.writeFileSync(f, entry);\n"],
    ["adds a desktop autostart entry"]);
  each(["const cfg = {'autostart': true}; fs.writeFileSync('c.json', JSON.stringify(cfg));",
    "fs.readdirSync(path.join(home, '.config', 'autostart'))"], []);
});

test("install time only, and hostile texts finish fast", () => {
  assert.deepEqual(installScriptRisk(UNIT_WRITER), ["installs a systemd service"]);
  assert.deepEqual(importTimeRisk(UNIT_WRITER, "js"), [[], null]);
  for (const text of ["systemctl -a".repeat(200_000), "| crontab ".repeat(200_000), "CurrentVersion\\Run ".repeat(200_000),
    "reg " + " ".repeat(1_000_000), "'systemd', 'user', ".repeat(100_000) + "fs.writeFileSync(", "LaunchAgents x\n".repeat(200_000),
    "(".repeat(1_000_000), "\n" + " ".repeat(1_000_000), "/etc/cron.d/x ".repeat(100_000) + "\n"]) {
    const start = performance.now();
    serviceReasons(text);
    assert.ok(performance.now() - start < 5000, text.slice(0, 30));
  }
});

test("an install hook's command and the script it runs", () => {
  const root = mkdtempSync(join(tmpdir(), "lz-svc-"));
  const out = mkdtempSync(join(tmpdir(), "lz-svc-out-"));
  try {
    const files = {
      "node_modules/p/package.json": JSON.stringify({ name: "p", version: "1.0.0",
        scripts: { postinstall: "systemctl --user enable --now p.service" } }),
      "node_modules/q/package.json": JSON.stringify({ name: "q", version: "1.0.0", scripts: { postinstall: "node index.js" } }),
      "node_modules/q/index.js": UNIT_WRITER,
    };
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    spawnSync(process.execPath, [CLI, root, "--deps", "--out-dir", out, "-q"], { encoding: "utf8" });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.issues.filter((i) => i.rule === "SC-INSTALL-HOOK").map((i) => [i.file.replaceAll("\\", "/"), i.sev, i.msg]).sort(), [
      ["node_modules/p/package.json", "CRITICAL", '"postinstall" script installs a systemd service.'],
      ["node_modules/q/package.json", "CRITICAL", "Install hook runs index.js, which installs a systemd service."]]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
