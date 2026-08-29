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
    println!("xtask no-std: building tpt-crypto-core for thumbv6m-none-eabi (no alloc) ...");
    // tpt-crypto-core is fully heapless; build it without default (std) features.
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "tpt-crypto-core",
            "--no-default-features",
            "--target",
            "thumbv6m-none-eabi",
        ])
        .status();
    match status {
        Ok(s) if s.success() => 0,
        Ok(_) => 1,
        Err(e) => {
            eprintln!("no-std: could not invoke cargo: {e}");
            1
        }
    }
}

fn kat_check() -> i32 {
    println!("xtask kat-check: not yet wired (no KAT corpus for tpt-crypto-core).");
    0
}

fn verify() -> i32 {
    println!("xtask verify: tpt-telos verification is a separate tool; not wired in this pass.");
    0
}

fn release_dry_run() -> i32 {
    // Publishable Phase 1 slice, in dependency order.
    let crates = ["tpt-crypto-core", "tpt-crypto-ct", "tpt-crypto-hash"];
    let mut worst = 0;
    for name in crates {
        println!("xtask release-dry-run: cargo publish --dry-run -p {name}");
        let status = Command::new("cargo")
            .args(["publish", "--dry-run", "-p", name])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => worst = 1,
            Err(e) => {
                eprintln!("release-dry-run: could not invoke cargo: {e}");
                worst = 1;
            }
        }
    }
    if worst == 0 {
        println!("release-dry-run: clean for the v0.1 publishable slice.");
    }
    worst
}

fn sbom() -> i32 {
    println!("xtask sbom: not yet implemented.");
    0
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
