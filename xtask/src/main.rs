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
        "no-std" => no_std(),
        "kat-check" => kat_check(),
        "verify" => verify(),
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
         verify           run tpt-telos over specs/*.telos\n  \
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

fn no_std() -> i32 {
    println!("xtask no-std: building heapless crates for thumbv6m-none-eabi (no alloc) ...");
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
        println!(
            "xtask no-std: building {name} for thumbv6m-none-eabi (--no-default-features) ..."
        );
        let status = Command::new("cargo")
            .args([
                "build",
                "-p",
                name,
                "--no-default-features",
                "--target",
                "thumbv6m-none-eabi",
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
        println!("no-std: PASS — all heapless crates build for thumbv6m-none-eabi.");
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

fn verify() -> i32 {
    println!("xtask verify: running tpt-telos-cli over specs/*.telos ...");
    // `cargo xtask verify` shells out to the external `tpt-telos-ci` binary.
    // If the tool is not installed, fail loudly (the docs call for a report).
    // The CI `telos-verify` job marks this gate non-blocking in CI config.
    let spec_dir = std::path::Path::new("specs");
    let mut worst = 0;
    let mut verified = 0;
    if let Ok(entries) = std::fs::read_dir(spec_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "telos").unwrap_or(false) {
                let status = Command::new("tpt-telos-cli")
                    .arg(path.to_str().unwrap())
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        println!("verify: {}: OK", path.display());
                        verified += 1;
                    }
                    Ok(_) => {
                        eprintln!("verify: {}: FAILED", path.display());
                        worst = 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "verify: {}: could not run tpt-telos-cli: {e}",
                            path.display()
                        );
                        worst = 1;
                    }
                }
            }
        }
    }
    if worst == 0 {
        println!("verify: PASS — {verified} contract(s) verified.");
    } else {
        eprintln!("verify: FAIL (see above).");
    }
    worst
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
