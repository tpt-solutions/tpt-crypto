//! Developer task runner for `tpt-crypto`.
//!
//! Run with `cargo xtask <command>`. This pass implements `leakage`
//! (the dudect-style Welch t-test harness) and stubs the remaining
//! cross-cutting commands declared in `todo.md` so the workspace builds.

use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let code = match cmd {
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
        "usage: cargo xtask <command>\n\ncommands:\n  leakage        run the dudect-style Welch t-test harness (tpt-crypto-ct)\n  no-std         build no_std crates for thumbv6m-none-eabi\n  kat-check     verify tests/kat/PROVENANCE.md sha256s\n  verify        run tpt-telos over specs/*.telos\n  release-dry-run  cargo publish --dry-run in topo order\n  sbom          emit an SBOM artifact\n"
    );
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
    println!("xtask no-std: building tpt-crypto-ct for thumbv6m-none-eabi (no alloc) ...");
    // The ct crate is fully heapless; build it without default (std) features.
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "tpt-crypto-ct",
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
    println!("xtask kat-check: not yet wired (no KAT corpus for tpt-crypto-ct).");
    0
}

fn verify() -> i32 {
    println!("xtask verify: tpt-telos verification is a separate tool; not wired in this pass.");
    0
}

fn release_dry_run() -> i32 {
    println!("xtask release-dry-run: run `cargo publish --dry-run -p tpt-crypto-ct`.");
    let status = Command::new("cargo")
        .args(["publish", "--dry-run", "-p", "tpt-crypto-ct"])
        .status();
    match status {
        Ok(s) if s.success() => 0,
        Ok(_) => 1,
        Err(e) => {
            eprintln!("release-dry-run: could not invoke cargo: {e}");
            1
        }
    }
}

fn sbom() -> i32 {
    println!("xtask sbom: not yet implemented.");
    0
}
