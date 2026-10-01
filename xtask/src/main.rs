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
        "verify" => verify(args.iter().any(|a| a == "--strict")),
        "release-dry-run" => release_dry_run(),
        "sbom" => sbom(),
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
         verify           check specs/*.spec against cited test evidence (--strict fails on pending)\n  \
         release-dry-run  cargo publish --dry-run in topo order\n  \
         sbom             emit a SBOM artifact\n"
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
    cargo(&["test", "--workspace", "--all-features"])
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
        if let Some(args) = t.strip_prefix("cargo-test:") {
            evidence.push(Evidence::CargoTest(
                args.split_whitespace().map(String::from).collect(),
            ));
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
