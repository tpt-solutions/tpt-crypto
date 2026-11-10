//! Developer task runner for `tpt-crypto`.
//!
//! Run with `cargo xtask <command>`. This pass implements `leakage`
//! (the dudect-style Welch t-test harness), `check` (fmt + clippy + deny),
//! and the cross-cutting commands declared in `todo.md`.

use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let code = match cmd {
        "check" => {
            let f = fmt();
            let c = clippy();
            let d = deny();
            f.max(c).max(d)
        }
        "fmt" => fmt(),
        "clippy" => clippy(),
        "test" => test(),
        "leakage" => leakage(),
        "no-std" => no_std(
            args.get(1)
                .map(String::as_str)
                .unwrap_or("thumbv6m-none-eabi"),
        ),
        "kat-check" => kat_check(),
        "exhaustive" => exhaustive(),
        "ct-asm" => ct_asm(),
        "verify" => verify(args.iter().any(|a| a == "--strict")),
        "release-dry-run" => release_dry_run(),
        "sbom" => sbom(),
        "new-primitive" => match args.get(1) {
            Some(name) => new_primitive(name),
            None => {
                eprintln!("usage: cargo xtask new-primitive <tpt-crypto-name>");
                1
            }
        },
        "wycheproof-fetch" => wycheproof_fetch(),
        "coverage" => coverage(),
        "doctor" => doctor(),
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            eprintln!("error: unknown xtask command `{other}`");
            print_help();
            1
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "usage: cargo xtask <command>\n\ncommands:\n  \
         check            fmt --check + clippy -D warnings + cargo deny\n  \
         fmt              cargo fmt --check\n  \
         clippy           clippy --all-targets --all-features -D warnings\n  \
         test             cargo test --workspace --all-features\n  \
         leakage          run the dudect-style Welch t-test harness (tpt-crypto-ct)\n  \
         no-std           build no_std crates for thumbv6m-none-eabi\n  \
         kat-check        verify tests/kat/PROVENANCE.md sha256s\n  \
         exhaustive       release-mode exhaustive bounded-domain checks (todo V1)\n  \
         ct-asm           binary-level constant-time check of probe functions (todo V3)\n  \
         verify           check specs/*.spec against cited test evidence (--strict fails on pending)\n  \
         release-dry-run  cargo publish --dry-run in topo order\n  \
         sbom             emit a SBOM artifact\n  \
         doctor           report toolchain, targets, nightly/miri, deny and fuzz status\n  \
         new-primitive    scaffold crates/<name> per AGENTS.md (name: tpt-crypto-*)\n  \
         wycheproof-fetch download pinned Wycheproof AEAD vectors and record sha256\n  \
         coverage         line/region coverage summary via cargo-llvm-cov (all features)\n"
    );
}

fn cargo(args: &[&str]) -> i32 {
    let status = Command::new("cargo").args(args).status();
    match status {
        Ok(s) if s.success() => 0,
        Ok(_) => 1,
        Err(e) => {
            eprintln!("xtask: could not invoke cargo: {e}");
            1
        }
    }
}

fn fmt() -> i32 {
    println!("xtask fmt: cargo fmt --check");
    cargo(&["fmt", "--check"])
}

fn clippy() -> i32 {
    println!("xtask clippy: clippy --all-targets --all-features -D warnings");
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ])
}

fn test() -> i32 {
    println!("xtask test: cargo test --workspace --all-features");
    let all = cargo(&["test", "--workspace", "--all-features"]);
    // `--all-features` enables `profile-cnsa2`, which compiles out the 2048-bit RSA
    // known-answer tests. Run the sig crate under `profile-modern` so they still run.
    println!("xtask test: cargo test -p tpt-crypto-sig --features alloc,profile-modern");
    let modern = cargo(&[
        "test",
        "-p",
        "tpt-crypto-sig",
        "--features",
        "alloc,profile-modern",
    ]);
    all.max(modern)
}

/// Run `tests/leakage.rs` for `tpt-crypto-ct` under the `leakage` feature.
fn leakage() -> i32 {
    println!("running dudect-style leakage harness for tpt-crypto-ct ...");
    let status = Command::new("cargo")
        .args([
            "test",
            "-p",
            "tpt-crypto-ct",
            "--features",
            "leakage",
            "--test",
            "leakage",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .status();
    match status {
        Ok(s) => {
            if s.success() {
                println!("leakage: PASS (no detectable leakage)");
                0
            } else {
                eprintln!("leakage: FAIL (see t-test output above)");
                1
            }
        }
        Err(e) => {
            eprintln!("leakage: could not invoke cargo: {e}");
            1
        }
    }
}

fn no_std(target: &str) -> i32 {
    println!("xtask no-std: building heapless crates for {target} (no alloc) ...");
    // Every substrate crate is `#![no_std]`; `std` is the default feature but
    // pulling the `alloc` path in requires the `alloc` feature explicitly.
    // For each crate whose ecosystem is heapless we build with
    // `--no-default-features` (no std, no alloc).
    let crates = [
        "tpt-crypto-core",
        "tpt-crypto-ct",
        "tpt-crypto-hash",
        "tpt-crypto-field",
        "tpt-crypto-curve",
        "tpt-crypto-aead",
        "tpt-crypto-kem",
        "tpt-crypto-sig",
    ];
    let mut worst = 0;
    for name in crates {
        println!("xtask no-std: building {name} for {target} (--no-default-features) ...");
        let status = Command::new("cargo")
            .args([
                "build",
                "-p",
                name,
                "--no-default-features",
                "--target",
                target,
            ])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => {
                eprintln!("no-std: FAILED for {name}");
                worst = 1;
            }
            Err(e) => {
                eprintln!("no-std: could not invoke cargo: {e}");
                worst = 1;
            }
        }
    }
    if worst == 0 {
        println!("no-std: PASS — all heapless crates build for {target}.");
    }
    worst
}

fn kat_check() -> i32 {
    // For every crate's `tests/kat/` dir, read `PROVENANCE.md` and verify any
    // file checksums recorded as a row `| \`<file>\` | <sha256> |` (the format
    // written by the shared xtask::write_provenance_checksums helper when KAT
    // vectors land). We use the workspace's own SHA-256 to keep the toolchain
    // self-hosting.
    const ROOT: &str = "crates";
    let mut worst = 0;
    let mut checked = 0;
    if let Ok(entries) = std::fs::read_dir(ROOT) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let kat_dir = entry.path().join("tests").join("kat");
            if !kat_dir.is_dir() {
                continue;
            }
            let prov = kat_dir.join("PROVENANCE.md");
            if !prov.is_file() {
                continue;
            }
            let content = match std::fs::read_to_string(&prov) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("kat-check: cannot read {}: {e}", prov.display());
                    worst = 1;
                    continue;
                }
            };
            for line in content.lines() {
                // Match `| `file` | <64-hex> |`
                let line = line.trim();
                let Some(rest) = line.strip_prefix('|') else {
                    continue;
                };
                let Some(rest) = rest.strip_suffix('|') else {
                    continue;
                };
                let mut cells = rest.split('|').map(|c| c.trim());
                let file = cells.next().filter(|f| f.len() > 2 && f.starts_with('`'));
                let hash = cells.next();
                if let (Some(f), Some(h)) = (file, hash) {
                    let file = &f[1..f.len() - 1]; // strip backticks
                                                   // Hash cell may be `` `hex` `` or bare `hex`.
                    let hash = if h.len() == 66 && h.starts_with('`') {
                        &h[1..65]
                    } else {
                        h
                    };
                    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        continue;
                    }
                    let path = kat_dir.join(file);
                    let hash = hash.to_ascii_lowercase();
                    if !path.is_file() {
                        eprintln!("kat-check: {}: listed file `{file}` does not exist", name);
                        worst = 1;
                        continue;
                    }
                    match sha256_file(&path) {
                        Ok(actual) if actual == hash => {
                            println!("kat-check: {name}: {file}: sha256 OK ({hash})");
                            checked += 1;
                        }
                        Ok(actual) => {
                            eprintln!(
                                "kat-check: {name}: {file}: sha256 MISMATCH (expected {hash}, got {actual})"
                            );
                            worst = 1;
                        }
                        Err(e) => {
                            eprintln!("kat-check: {name}: {file}: {e}");
                            worst = 1;
                        }
                    }
                }
            }
        }
    }
    if worst == 0 {
        println!(
            "kat-check: PASS — {checked} vector file checksum(s) verified against PROVENANCE.md"
        );
    } else {
        eprintln!("kat-check: FAIL — see mismatches above.");
    }
    worst
}

/// SHA-256 of a file, hex-encoded, computed via `tpt-crypto-hash`.
fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    use tpt_crypto_hash::sha2::sha256;
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let digest = sha256(&bytes);
    Ok(hex_of(&digest))
}

/// Minimal hex encoder (kept dependency-free and no_std-compatible).
fn hex_of(bytes: &[u8]) -> String {
    fn nibble(b: u8) -> char {
        match b {
            0..=9 => (b'0' + b) as char,
            _ => (b'a' + b - 10) as char,
        }
    }
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0F));
    }
    s
}

/// One machine-checked claim from a spec's `evidence:` block.
enum Evidence {
    /// `cargo-test: <args>` — run `cargo test <args>`; must pass and run ≥ 1 test.
    CargoTest(Vec<String>),
    /// `exhaustive: <pkg> <test-target> <test-name>` — run one exhaustive
    /// bounded-domain test (`#[ignore]`d or not) in release mode with all features,
    /// selected by exact name; it must pass and run exactly that test.
    Exhaustive {
        pkg: String,
        target: String,
        test: String,
    },
    /// `ct-asm: <pkg> <probe-target>` — the binary-level scan of that probe target
    /// (`cargo xtask ct-asm`) must find no conditional jump in its `probe_*` functions.
    CtAsm { pkg: String, target: String },
    /// `pending: <reason>` — contract acknowledged but not yet backed by tests.
    Pending(String),
}

/// Parse a `specs/*.spec` file: require the `spec <name>` header (matching the
/// file stem), an `ensures:` section and a non-empty `evidence:` section.
fn parse_spec(stem: &str, text: &str) -> Result<Vec<Evidence>, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    match lines.next().map(str::trim) {
        Some(h) if h == format!("spec {stem}") => {}
        other => return Err(format!("first line must be `spec {stem}`, found {other:?}")),
    }
    let mut has_ensures = false;
    let mut in_evidence = false;
    let mut evidence = Vec::new();
    for line in text.lines() {
        let is_section = !line.starts_with(char::is_whitespace) && line.trim_end().ends_with(':');
        if is_section {
            has_ensures |= line.trim() == "ensures:";
            in_evidence = line.trim() == "evidence:";
            continue;
        }
        if !in_evidence || line.trim().is_empty() {
            continue;
        }
        let t = line.trim();
        if t.starts_with('#') {
            continue; // comment line inside an evidence block
        }
        if let Some(args) = t.strip_prefix("cargo-test:") {
            evidence.push(Evidence::CargoTest(
                args.split_whitespace().map(String::from).collect(),
            ));
        } else if let Some(rest) = t.strip_prefix("exhaustive:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match parts.as_slice() {
                [pkg, target, test] => evidence.push(Evidence::Exhaustive {
                    pkg: pkg.to_string(),
                    target: target.to_string(),
                    test: test.to_string(),
                }),
                _ => {
                    return Err(format!(
                        "exhaustive entry needs `<pkg> <test-target> <test-name>`: `{t}`"
                    ))
                }
            }
        } else if let Some(rest) = t.strip_prefix("ct-asm:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match parts.as_slice() {
                [pkg, target] => evidence.push(Evidence::CtAsm {
                    pkg: pkg.to_string(),
                    target: target.to_string(),
                }),
                _ => return Err(format!("ct-asm entry needs `<pkg> <probe-target>`: `{t}`")),
            }
        } else if let Some(why) = t.strip_prefix("pending:") {
            evidence.push(Evidence::Pending(why.trim().to_string()));
        } else {
            return Err(format!("unknown evidence entry: `{t}`"));
        }
    }
    if !has_ensures {
        return Err("missing `ensures:` section".into());
    }
    if evidence.is_empty() {
        return Err("missing or empty `evidence:` section".into());
    }
    Ok(evidence)
}

/// Run `cargo test <args>`; succeed only if it passes and at least one test ran.
/// Run one named exhaustive test in release mode and require that it ran and passed.
fn run_exhaustive(pkg: &str, target: &str, test: &str) -> Result<(), String> {
    let out = Command::new("cargo")
        .args([
            "test",
            "--release",
            "--all-features",
            "-p",
            pkg,
            "--test",
            target,
            "--",
            "--include-ignored",
            "--exact",
            test,
        ])
        .output()
        .map_err(|e| format!("could not invoke cargo: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!(
            "cargo test failed\n{}\n{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let ran_one = stdout.lines().any(|l| l.trim() == "running 1 test");
    let passed = stdout
        .lines()
        .any(|l| l.starts_with("test result: ok. 1 passed"));
    if !(ran_one && passed) {
        return Err(format!("expected exactly one passing test named `{test}`"));
    }
    Ok(())
}

fn run_evidence(args: &[String]) -> Result<(), String> {
    let out = Command::new("cargo")
        .arg("test")
        .args(args)
        .output()
        .map_err(|e| format!("could not invoke cargo: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!(
            "cargo test failed\n{}\n{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let passed: u64 = stdout
        .lines()
        .filter(|l| l.starts_with("test result: ok."))
        .filter_map(|l| {
            l.split("ok. ")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .sum();
    if passed == 0 {
        return Err("filter matched no tests (stale test name?)".into());
    }
    Ok(())
}

/// In-house contract checker. Each `specs/*.spec` binds its `ensures:` claims
/// to named tests in an `evidence:` block; the spec holds only if every cited
/// test exists, runs, and passes. `pending:` entries are reported (and fail
/// under `--strict`) so unproven contracts stay visible.
fn verify(strict: bool) -> i32 {
    println!("xtask verify: checking specs/*.spec against cited test evidence ...");
    let mut paths: Vec<_> = std::fs::read_dir("specs")
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    paths.retain(|p| p.extension().is_some_and(|e| e == "spec"));
    paths.sort();
    let (mut verified, mut pending, mut failed) = (0, 0, 0);
    for path in &paths {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("verify: {}: unreadable: {e}", path.display());
                failed += 1;
                continue;
            }
        };
        let evidence = match parse_spec(stem, &text) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("verify: {}: FAILED — {e}", path.display());
                failed += 1;
                continue;
            }
        };
        let mut spec_ok = true;
        let mut spec_pending = false;
        for ev in &evidence {
            match ev {
                Evidence::CargoTest(args) => {
                    if let Err(e) = run_evidence(args) {
                        eprintln!(
                            "verify: {}: FAILED — cargo test {}: {e}",
                            path.display(),
                            args.join(" ")
                        );
                        spec_ok = false;
                    }
                }
                Evidence::Exhaustive { pkg, target, test } => {
                    if let Err(e) = run_exhaustive(pkg, target, test) {
                        eprintln!(
                            "verify: {}: FAILED — exhaustive {pkg} {target} {test}: {e}",
                            path.display()
                        );
                        spec_ok = false;
                    }
                }
                Evidence::CtAsm { pkg, target } => {
                    if let Err(e) = ct_asm_one(pkg, target, true) {
                        eprintln!(
                            "verify: {}: FAILED — ct-asm {pkg} {target}: {e}",
                            path.display()
                        );
                        spec_ok = false;
                    }
                }
                Evidence::Pending(why) => {
                    println!("verify: {}: PENDING — {why}", path.display());
                    spec_pending = true;
                }
            }
        }
        if !spec_ok {
            failed += 1;
        } else if spec_pending {
            pending += 1;
        } else {
            println!("verify: {}: OK", path.display());
            verified += 1;
        }
    }
    println!("verify: {verified} verified, {pending} pending, {failed} failed.");
    if failed > 0 || (strict && pending > 0) {
        eprintln!("verify: FAIL (see above).");
        1
    } else {
        println!("verify: PASS");
        0
    }
}

fn release_dry_run() -> i32 {
    // All 11 crates, in dependency order (lower never depends on higher).
    let crates = [
        "tpt-crypto-core",
        "tpt-crypto-ct",
        "tpt-crypto-hash",
        "tpt-crypto-field",
        "tpt-crypto-curve",
        "tpt-crypto-aead",
        "tpt-crypto-kem",
        "tpt-crypto-sig",
        "tpt-crypto-zk",
        "tpt-crypto-mpc",
        "tpt-crypto",
    ];
    let mut worst = 0;
    for name in crates {
        println!("xtask release-dry-run: cargo publish --dry-run -p {name}");
        // `--allow-dirty`: this pass explicitly does not commit/publish, so a
        // dirty working tree is expected; the dry-run still validates packaging
        // and crates.io metadata.
        let status = Command::new("cargo")
            .args(["publish", "--dry-run", "--allow-dirty", "-p", name])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => {
                eprintln!("release-dry-run: FAILED for {name}");
                worst = 1;
            }
            Err(e) => {
                eprintln!("release-dry-run: could not invoke cargo: {e}");
                worst = 1;
            }
        }
    }
    if worst == 0 {
        println!("release-dry-run: clean for all 11 crates.");
    }
    worst
}

fn sbom() -> i32 {
    // Emit a compact CycloneDX-lite JSON SBOM derived from `cargo metadata`.
    // The full spdx/cyclonedx tooling pulls a heavy dep chain; this keeps the
    // build self-containing and dependency-free while still reporting name,
    // version, source, and dependency edges for every crate in the workspace.
    println!("xtask sbom: generating target/sbom.json from cargo metadata ...");
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--all-features"])
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sbom: could not invoke cargo metadata: {e}");
            return 1;
        }
    };
    if !output.status.success() {
        eprintln!(
            "sbom: cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return 1;
    }
    let meta: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sbom: could not parse cargo metadata JSON: {e}");
            return 1;
        }
    };
    let packages = meta
        .get("packages")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let mut components = Vec::new();
    if let Some(arr) = packages.as_array() {
        for pkg in arr {
            let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let source = pkg.get("source").and_then(|v| v.as_str()).unwrap_or("path");
            components.push(serde_json::json!({
                "type": "library",
                "name": name,
                "version": version,
                "supplier": "TPT Solutions",
                "source": source,
            }));
        }
    }
    let sbom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "tpt-crypto",
                "version": "0.1.0"
            }
        },
        "components": components,
    });
    let out_path = std::path::Path::new("target").join("sbom.json");
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&sbom).unwrap_or_default(),
    ) {
        Ok(_) => {
            println!("sbom: wrote {}", out_path.display());
            0
        }
        Err(e) => {
            eprintln!("sbom: could not write {}: {e}", out_path.display());
            1
        }
    }
}

fn deny() -> i32 {
    println!("xtask deny: cargo deny check");
    // `cargo-deny` may be installed as the standalone `cargo-deny` binary or as
    // the cargo subcommand `cargo deny`.
    let has_standalone = which("cargo-deny");
    let mut cmd = Command::new(if has_standalone {
        "cargo-deny"
    } else {
        "cargo"
    });
    if !has_standalone {
        cmd.arg("deny");
    }
    cmd.args(["check"]);
    match cmd.status() {
        Ok(s) if s.success() => 0,
        Ok(_) => 1,
        Err(e) => {
            eprintln!("deny: could not invoke cargo-deny: {e}");
            1
        }
    }
}

/// Environment report. Exits non-zero only when a required tool is missing
/// (stable cargo, rustfmt, clippy, cargo-deny); optional items are reported as
/// `missing` but do not fail the run.
fn doctor() -> i32 {
    println!("xtask doctor: checking development environment");
    let mut required_missing = 0;

    let mut check = |label: &str, ok: bool, required: bool| {
        let tag = match (ok, required) {
            (true, _) => "ok     ",
            (false, true) => "MISSING",
            (false, false) => "absent ",
        };
        println!("  [{tag}] {label}");
        if !ok && required {
            required_missing += 1;
        }
    };

    check("cargo (stable)", probe("cargo", &["--version"]), true);
    check("rustc (stable)", probe("rustc", &["--version"]), true);
    let installed_components = capture("rustup", &["component", "list", "--installed"]);
    check(
        "rustfmt component",
        installed_components.contains("rustfmt"),
        true,
    );
    check(
        "clippy component",
        installed_components.contains("clippy"),
        true,
    );

    let installed_targets = capture("rustup", &["target", "list", "--installed"]);
    for target in [
        "thumbv6m-none-eabi",
        "thumbv7em-none-eabihf",
        "wasm32-unknown-unknown",
    ] {
        check(
            &format!("target {target} (no_std / wasm builds)"),
            installed_targets.lines().any(|l| l.trim() == target),
            false,
        );
    }

    check(
        "nightly toolchain",
        probe("cargo", &["+nightly", "--version"]),
        false,
    );
    check(
        "miri (nightly)",
        probe("cargo", &["+nightly", "miri", "--version"]),
        false,
    );
    check(
        "cargo-deny",
        which("cargo-deny") || probe("cargo", &["deny", "--version"]),
        true,
    );
    check("cargo-fuzz", probe("cargo", &["fuzz", "--version"]), false);

    if required_missing == 0 {
        println!("xtask doctor: all required tools present");
        0
    } else {
        println!("xtask doctor: {required_missing} required tool(s) missing");
        1
    }
}

/// True when `program args...` runs and exits successfully (output discarded).
fn probe(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Stdout of `program args...`, or empty on failure.
fn capture(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// `cargo xtask new-primitive <name>`: scaffold a crate under `crates/<name>/`
/// following AGENTS.md (no_std, workspace lints, README, CHANGELOG, crates.io
/// metadata), and add it to the root `[workspace.dependencies]`.
///
/// The registry entry in `../tpt-rust-map/registry.toml` is not written here:
/// that repo sits outside this workspace. The command prints the line to add.
fn new_primitive(name: &str) -> i32 {
    if !name.starts_with("tpt-crypto-")
        || name.len() > 64
        || name.contains("--")
        || name.ends_with('-')
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        eprintln!(
            "xtask new-primitive: name must start with `tpt-crypto-`, use lowercase letters, \
             digits and single hyphens, and be at most 64 characters"
        );
        return 1;
    }
    let dir = std::path::Path::new("crates").join(name);
    if dir.exists() {
        eprintln!("xtask new-primitive: {} already exists", dir.display());
        return 1;
    }

    let cargo_toml = format!(
        "[package]\n\
         name = \"{name}\"\n\
         version = \"0.1.0\"\n\
         edition.workspace = true\n\
         rust-version.workspace = true\n\
         license.workspace = true\n\
         authors.workspace = true\n\
         description = \"{name}: scaffold, not yet implemented.\"\n\
         readme = \"README.md\"\n\
         repository.workspace = true\n\
         homepage.workspace = true\n\
         documentation = \"https://docs.rs/{name}\"\n\
         keywords = [\"cryptography\", \"no-std\", \"constant-time\", \"crypto\"]\n\
         categories = [\"cryptography\", \"no-std\"]\n\
         \n\
         [dependencies]\n\
         \n\
         [lints]\n\
         workspace = true\n"
    );
    let lib_rs = format!(
        "//! `{name}`: scaffold. Replace this with the primitive's documentation.\n\
         \n\
         #![no_std]\n\
         #![forbid(unsafe_code)]\n\
         #![warn(missing_docs)]\n"
    );
    let readme = format!(
        "# {name}\n\
         \n\
         Scaffold, not yet implemented. Part of the tpt-crypto workspace.\n\
         \n\
         ## License\n\
         \n\
         MIT OR Apache-2.0\n"
    );
    let changelog = "# Changelog\n\n## 0.1.0 — unreleased\n\n- Scaffold.\n";
    let provenance = "# KAT PROVENANCE\n\nNo vectors yet. Record each vector file here with its source and sha256.\n";

    let writes: [(std::path::PathBuf, &str); 5] = [
        (dir.join("Cargo.toml"), cargo_toml.as_str()),
        (dir.join("src").join("lib.rs"), lib_rs.as_str()),
        (dir.join("README.md"), readme.as_str()),
        (dir.join("CHANGELOG.md"), changelog),
        (
            dir.join("tests").join("kat").join("PROVENANCE.md"),
            provenance,
        ),
    ];
    for (path, body) in writes.iter() {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "xtask new-primitive: cannot create {}: {e}",
                    parent.display()
                );
                return 1;
            }
        }
        if let Err(e) = std::fs::write(path, body) {
            eprintln!("xtask new-primitive: cannot write {}: {e}", path.display());
            return 1;
        }
    }

    match add_workspace_dependency(name) {
        Ok(true) => println!("xtask new-primitive: added `{name}` to [workspace.dependencies]"),
        Ok(false) => println!("xtask new-primitive: `{name}` already in [workspace.dependencies]"),
        Err(e) => {
            eprintln!("xtask new-primitive: could not update Cargo.toml: {e}");
            return 1;
        }
    }

    println!("xtask new-primitive: scaffolded {}", dir.display());
    println!("next steps:");
    println!("  - implement the primitive and add KATs under tests/kat/ (PROVENANCE.md)");
    println!("  - register the crate in ../tpt-rust-map/registry.toml with status = \"git\"");
    println!("    (that repo is outside this workspace; add it by hand)");
    0
}

/// Insert `name = { version, path, default-features = false }` after the last
/// `tpt-crypto-*` entry of `[workspace.dependencies]`. Returns `Ok(false)` when
/// the entry is already present.
fn add_workspace_dependency(name: &str) -> Result<bool, String> {
    let path = "Cargo.toml";
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let prefix = format!("{name} = ");
    if text.lines().any(|l| l.starts_with(&prefix)) {
        return Ok(false);
    }
    let mut out: Vec<String> = Vec::new();
    let mut in_section = false;
    let mut insert_at: Option<usize> = None;
    for line in text.lines() {
        if line.starts_with('[') {
            in_section = line.trim() == "[workspace.dependencies]";
        }
        out.push(line.to_string());
        if in_section && line.starts_with("tpt-crypto-") {
            insert_at = Some(out.len());
        }
    }
    let at = insert_at.ok_or("no tpt-crypto-* entries in [workspace.dependencies]")?;
    out.insert(
        at,
        format!("{name} = {{ version = \"0.1.0\", path = \"crates/{name}\", default-features = false }}"),
    );
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    std::fs::write(path, joined).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Wycheproof files fetched by `wycheproof-fetch`, with the crate that uses them.
const WYCHEPROOF_BASE: &str =
    "https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/";
const WYCHEPROOF_FILES: &[&str] = &["aes_gcm_test.json", "chacha20_poly1305_test.json"];
const WYCHEPROOF_DEST: &str = "crates/tpt-crypto-aead/tests/kat/wycheproof";
const WYCHEPROOF_SECTION: &str = "## Wycheproof (fetched by `cargo xtask wycheproof-fetch`)";

/// `cargo xtask wycheproof-fetch`: download the pinned Wycheproof AEAD vector
/// files into `tests/kat/wycheproof/`, check that each is a Wycheproof JSON
/// document, and record its sha256 in the crate's `PROVENANCE.md` in the form
/// `kat-check` reads.
fn wycheproof_fetch() -> i32 {
    let dest = std::path::Path::new(WYCHEPROOF_DEST);
    if let Err(e) = std::fs::create_dir_all(dest) {
        eprintln!("wycheproof-fetch: cannot create {}: {e}", dest.display());
        return 1;
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for file in WYCHEPROOF_FILES {
        let url = format!("{WYCHEPROOF_BASE}{file}");
        let target = dest.join(file);
        println!("wycheproof-fetch: GET {url}");
        let status = Command::new("curl")
            .args(["-fsSL", "--retry", "2", "-o"])
            .arg(&target)
            .arg(&url)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("wycheproof-fetch: curl failed for {url} ({s})");
                return 1;
            }
            Err(e) => {
                eprintln!("wycheproof-fetch: could not run curl: {e}");
                return 1;
            }
        }
        // Sanity check: a Wycheproof file is a JSON object with `testGroups`.
        let body = match std::fs::read_to_string(&target) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("wycheproof-fetch: cannot read {}: {e}", target.display());
                return 1;
            }
        };
        if !body.trim_start().starts_with('{') || !body.contains("\"testGroups\"") {
            eprintln!("wycheproof-fetch: {file} is not a Wycheproof test file");
            return 1;
        }
        match sha256_file(&target) {
            Ok(h) => rows.push((format!("wycheproof/{file}"), h)),
            Err(e) => {
                eprintln!("wycheproof-fetch: {e}");
                return 1;
            }
        }
    }

    if let Err(e) = write_wycheproof_provenance(&rows) {
        eprintln!("wycheproof-fetch: cannot update PROVENANCE.md: {e}");
        return 1;
    }
    for (file, hash) in &rows {
        println!("wycheproof-fetch: {file}  sha256 {hash}");
    }
    println!("wycheproof-fetch: done; run `cargo xtask kat-check` to verify");
    0
}

/// Rewrite the Wycheproof section of the aead crate's PROVENANCE.md, keeping
/// everything before it.
fn write_wycheproof_provenance(rows: &[(String, String)]) -> Result<(), String> {
    let path = std::path::Path::new(WYCHEPROOF_DEST)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("PROVENANCE.md");
    // Normalise line endings so a CRLF checkout does not mix with the LF rows.
    let existing = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    let head = match existing.find(WYCHEPROOF_SECTION) {
        Some(i) => &existing[..i],
        None => existing.as_str(),
    };
    let mut section = String::new();
    section.push_str(WYCHEPROOF_SECTION);
    section.push_str("\n\n");
    section.push_str(
        "Source: <https://github.com/C2SP/wycheproof> `testvectors_v1/` (master), \
         fetched by `cargo xtask wycheproof-fetch`. Apache-2.0.\n\n",
    );
    section.push_str("| File | sha256 |\n| --- | --- |\n");
    for (file, hash) in rows {
        section.push_str(&format!("| `{file}` | {hash} |\n"));
    }
    let mut out = head.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(&section);
    std::fs::write(&path, out).map_err(|e| e.to_string())
}

/// `cargo xtask exhaustive`: run the `#[ignore]`d exhaustive checks (todo V1) in
/// release mode. These cover the full `u16` constant-time domain, the full `i32`
/// range for `freeze`, and the documented ML-KEM Montgomery domain. Each test is
/// named in the output so a failure can be traced to its check.
fn exhaustive() -> i32 {
    const SUITES: &[(&str, &str, &[&str])] = &[
        ("tpt-crypto-ct", "exhaustive", &[]),
        ("tpt-crypto-kem", "exhaustive", &["--features", "alloc"]),
        ("tpt-crypto-sig", "exhaustive", &["--features", "alloc"]),
        ("tpt-crypto-field", "small_field", &[]),
    ];
    let mut worst = 0;
    for (pkg, target, extra) in SUITES {
        let mut args: Vec<&str> = vec!["test", "--release", "-p", pkg, "--test", target];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "--ignored"]);
        println!("xtask exhaustive: cargo {}", args.join(" "));
        worst = worst.max(cargo(&args));
    }
    if worst == 0 {
        println!("xtask exhaustive: PASS (bounded-domain checks; not formal proofs)");
    }
    worst
}

/// `cargo xtask ct-asm`: binary-level constant-time check (todo V3).
///
/// Compiles each probe test target to release assembly with `--emit asm` and scans
/// every `probe_*` function body for conditional jumps. A conditional jump in a
/// probe means the compiler turned the primitive into a branch, and that branch
/// can depend on a secret. The command fails on any jump and also when no probe is
/// found, so an empty scan cannot pass.
fn ct_asm() -> i32 {
    // (package, probe test target)
    // (package, probe test target, strict). Strict targets fail on any conditional
    // jump. Report-only targets are composite functions whose jumps have not been
    // triaged yet (loops over public lengths, overflow checks); they are listed by
    // mnemonic and do not fail the run.
    const PROBES: &[(&str, &str, bool)] = &[
        ("tpt-crypto-ct", "ct_asm_probe", true),
        ("tpt-crypto-kem", "kem_asm_probe", false),
        ("tpt-crypto-kem", "kem_pack_asm_probe", false),
        ("tpt-crypto-aead", "aead_asm_probe", true),
        ("tpt-crypto-field", "field_asm_probe", true),
        ("tpt-crypto-curve", "curve_asm_probe", true),
        ("tpt-crypto-curve", "curve_mul_asm_probe", false),
    ];
    let mut worst = 0;
    for (pkg, target, strict) in PROBES {
        match ct_asm_one(pkg, target, *strict) {
            Ok(summary) => println!("ct-asm: {summary}"),
            Err(e) => {
                eprintln!("ct-asm: {pkg} {target}: {e}");
                worst = 1;
            }
        }
    }
    if worst == 0 {
        println!("ct-asm: PASS for strict targets (no conditional jumps in their probe functions). Report-only targets are not triaged yet. This is a static check, not a timing proof.");
    }
    worst
}

/// A probe label is a plain `probe_*` symbol, or a mangled name whose `probe_`
/// component carries its length prefix (a digit right before it, as in `20probe_…`).
/// The digit test keeps std functions such as `small_probe_read` out.
fn is_probe_label(name: &str) -> bool {
    if name.contains(char::is_whitespace) {
        return false;
    }
    if name.starts_with("probe_") {
        return true;
    }
    name.match_indices("probe_")
        .any(|(i, _)| i > 0 && name.as_bytes()[i - 1].is_ascii_digit())
}

fn ct_asm_one(pkg: &str, target: &str, strict: bool) -> Result<String, String> {
    // Cargo treats the test target as up to date and does not re-emit assembly, so
    // clean the package first and remove any earlier output. Otherwise the scan
    // reads a stale file, or none.
    let _ = Command::new("cargo")
        .args(["clean", "--release", "-p", pkg])
        .status();
    let deps = std::path::Path::new("target/release/deps");
    let prefix = format!("{}-", target.replace('-', "_"));
    if let Ok(entries) = std::fs::read_dir(deps) {
        for e in entries.flatten() {
            let p = e.path();
            let stale = p.extension().is_some_and(|x| x == "s")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix));
            if stale {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let status = Command::new("cargo")
        .args([
            "rustc",
            "--release",
            "-p",
            pkg,
            "--test",
            target,
            "--",
            "--emit",
            "asm",
            "-C",
            "codegen-units=1",
        ])
        .status()
        .map_err(|e| format!("could not invoke cargo: {e}"))?;
    if !status.success() {
        return Err("cargo rustc --emit asm failed".into());
    }
    let asm = std::fs::read_dir(deps)
        .map_err(|e| format!("{}: {e}", deps.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "s")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .ok_or("no assembly file produced")?;
    let text = std::fs::read_to_string(&asm).map_err(|e| format!("{}: {e}", asm.display()))?;

    let mut current: Option<String> = None;
    let mut probes = 0usize;
    let mut violations = Vec::new();
    for line in text.lines() {
        if let Some(name) = line.strip_suffix(':') {
            if is_probe_label(name) {
                current = Some(name.to_string());
                probes += 1;
            } else if !name.starts_with('.') {
                current = None;
            }
            continue;
        }
        if line.starts_with(".Lfunc_end") {
            current = None;
            continue;
        }
        let Some(fname) = &current else { continue };
        let op = line.split_whitespace().next().unwrap_or("");
        if op.starts_with('j') && op != "jmp" {
            violations.push(format!("{fname}: {}", line.trim()));
        }
    }

    if probes == 0 {
        return Err(format!("no probe_* functions found in {}", asm.display()));
    }
    if !strict {
        let mut by_op: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for v in &violations {
            let op = v
                .rsplit(": ")
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            *by_op.entry(op.to_string()).or_default() += 1;
        }
        let ops: Vec<String> = by_op.iter().map(|(k, v)| format!("{k} x{v}")).collect();
        return Ok(format!(
            "{pkg} {target}: {probes} probe-labelled function(s), {} conditional jump(s) NOT YET TRIAGED (report only): {}",
            violations.len(),
            ops.join(", ")
        ));
    }
    if !violations.is_empty() {
        return Err(format!(
            "{} conditional jump(s) in probe functions:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(format!(
        "{pkg} {target}: {probes} probe-labelled function(s), 0 conditional jumps"
    ))
}

/// Cheap `Path::exists`-style probe for an executable on `PATH`.
fn which(name: &str) -> bool {
    Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `cargo xtask coverage`: line and region coverage over the whole workspace with
/// every feature enabled, via `cargo-llvm-cov`. Prints the summary table only; it
/// does not gate on a threshold. Fails with a clear message when the tool is absent.
fn coverage() -> i32 {
    let installed = Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !installed {
        eprintln!("xtask coverage: cargo-llvm-cov is not installed (cargo install cargo-llvm-cov)");
        return 1;
    }
    cargo(&[
        "llvm-cov",
        "--workspace",
        "--all-features",
        "--summary-only",
    ])
}
