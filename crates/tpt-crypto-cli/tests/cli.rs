//! End-to-end tests: run the built `tpt-crypto` binary and check its output,
//! exit codes and files.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tpt-crypto"))
}

/// A fresh scratch directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tpt-cli-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("run tpt-crypto")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

#[test]
fn selftest_passes() {
    let o = run(&["selftest"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), "selftest: OK");
}

#[test]
fn hash_of_abc_matches_fips_180_4() {
    let dir = scratch("hash");
    let input = p(&dir, "in.txt");
    std::fs::write(&input, b"abc").unwrap();
    let o = run(&["hash", &input]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn random_prints_requested_length() {
    let o = run(&["random", "17"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o).len(), 34);
}

#[test]
fn sign_and_verify_round_trip_and_tampering() {
    let dir = scratch("sign");
    let seed = p(&dir, "seed.hex");
    let public = p(&dir, "pub.hex");
    let msg = p(&dir, "msg.txt");
    let sig = p(&dir, "sig.hex");
    std::fs::write(&msg, b"hello").unwrap();

    assert_eq!(code(&run(&["sign-keygen", &seed, &public])), 0);
    assert_eq!(code(&run(&["sign", &seed, &msg, &sig])), 0);

    let ok = run(&["verify", &public, &msg, &sig]);
    assert_eq!(code(&ok), 0);
    assert_eq!(stdout(&ok), "OK");

    std::fs::write(&msg, b"hellO").unwrap();
    let bad = run(&["verify", &public, &msg, &sig]);
    assert_eq!(code(&bad), 1);
    assert_eq!(stdout(&bad), "FAIL");
}

#[test]
fn sign_keygen_refuses_to_overwrite() {
    let dir = scratch("overwrite");
    let seed = p(&dir, "seed.hex");
    let public = p(&dir, "pub.hex");
    assert_eq!(code(&run(&["sign-keygen", &seed, &public])), 0);
    let again = run(&["sign-keygen", &seed, &public]);
    assert_eq!(code(&again), 2);
    assert!(String::from_utf8_lossy(&again.stderr).contains("tpt-crypto"));
}

#[test]
fn seal_and_open_round_trip_and_tampering() {
    let dir = scratch("seal");
    let key = p(&dir, "key.hex");
    let plain = p(&dir, "plain.bin");
    let sealed = p(&dir, "sealed.bin");
    let opened = p(&dir, "opened.bin");
    std::fs::write(&plain, b"attack at dawn").unwrap();

    assert_eq!(code(&run(&["seal-keygen", &key])), 0);
    assert_eq!(code(&run(&["seal", &key, &plain, &sealed])), 0);
    assert_eq!(code(&run(&["open", &key, &sealed, &opened])), 0);
    assert_eq!(std::fs::read(&opened).unwrap(), b"attack at dawn");

    // Flip one ciphertext byte: authentication must fail and no output is written.
    let mut bytes = std::fs::read(&sealed).unwrap();
    bytes[30] ^= 1;
    std::fs::write(&sealed, &bytes).unwrap();
    let remove = p(&dir, "should-not-exist.bin");
    let o = run(&["open", &key, &sealed, &remove]);
    assert_eq!(code(&o), 1);
    assert!(!Path::new(&remove).exists());
}

#[test]
fn stdin_input_is_accepted() {
    use std::io::Write;
    let mut child = bin()
        .args(["hash", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"abc").unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn usage_errors_exit_two() {
    assert_eq!(code(&run(&["no-such-command"])), 2);
    assert_eq!(code(&run(&["hash"])), 2);
    assert_eq!(code(&run(&["random", "lots"])), 2);
}

#[test]
fn kem_round_trip_and_implicit_rejection() {
    let dir = scratch("kem");
    let seed = p(&dir, "seed.hex");
    let public = p(&dir, "pub.hex");
    let ss_sent = p(&dir, "ss-sent.hex");
    let ct = p(&dir, "ct.hex");
    let ss_got = p(&dir, "ss-got.hex");

    assert_eq!(code(&run(&["kem-keygen", &seed, &public])), 0);
    assert_eq!(code(&run(&["kem-encap", &public, &ss_sent, &ct])), 0);
    assert_eq!(code(&run(&["kem-decap", &seed, &ct, &ss_got])), 0);
    assert_eq!(
        std::fs::read_to_string(&ss_sent).unwrap(),
        std::fs::read_to_string(&ss_got).unwrap()
    );

    // A tampered ciphertext is not an error: ML-KEM implicit rejection gives a
    // different secret. The X25519 component is checked too, so flip the ML-KEM part.
    let hex = std::fs::read_to_string(&ct).unwrap();
    let mut bytes = hex.trim().to_string();
    let flipped = if bytes.as_bytes()[10] == b'0' {
        '1'
    } else {
        '0'
    };
    bytes.replace_range(10..11, &flipped.to_string());
    std::fs::write(&ct, format!("{bytes}\n")).unwrap();
    let ss_bad = p(&dir, "ss-bad.hex");
    assert_eq!(code(&run(&["kem-decap", &seed, &ct, &ss_bad])), 0);
    assert_ne!(
        std::fs::read_to_string(&ss_sent).unwrap(),
        std::fs::read_to_string(&ss_bad).unwrap()
    );
}

#[test]
fn kem_decap_rejects_wrong_length_ciphertext() {
    let dir = scratch("kem-len");
    let seed = p(&dir, "seed.hex");
    let public = p(&dir, "pub.hex");
    let ct = p(&dir, "short.hex");
    let ss = p(&dir, "ss.hex");
    assert_eq!(code(&run(&["kem-keygen", &seed, &public])), 0);
    std::fs::write(&ct, "00ff\n").unwrap();
    assert_eq!(code(&run(&["kem-decap", &seed, &ct, &ss])), 2);
}

#[test]
fn bench_runs_and_lists_operations() {
    let o = run(&["bench", "1"]);
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    for name in ["sha256", "ed25519 sign", "x-wing decapsulate"] {
        assert!(out.contains(name), "missing {name}: {out}");
    }
    assert_eq!(code(&run(&["bench", "0"])), 2);
}
