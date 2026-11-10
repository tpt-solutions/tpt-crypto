//! `tpt-crypto`: command-line front end to the tpt-crypto recipes.
//!
//! Dependency-free: arguments, hex and file handling are written out by hand.
//! Key files are hex text. Output files are never overwritten. `-` means stdin
//! for input and stdout for `random`.
//!
//! Exit codes: `0` success, `1` a check failed (signature, authentication or
//! self-test), `2` usage or I/O error.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use tpt_crypto::easy;
use tpt_crypto::kem::xwing;
use tpt_crypto::prelude::OsRng;
use tpt_crypto::sig::ed25519;

const USAGE: &str = "\
usage: tpt-crypto <command> [args]

commands:
  selftest                       run the power-on known-answer tests
  hash <in|->                    SHA-256 of the input, as hex
  random <bytes>                 OS-RNG bytes, as hex (to stdout)
  sign-keygen <seed-out> <pub-out>
                                 new Ed25519 key pair (hex files)
  sign <seed-file> <in|-> <sig-out>
                                 Ed25519 signature (hex)
  verify <pub-file> <in|-> <sig-file>
                                 check a signature; prints OK or FAIL
  seal-keygen <key-out>          new 256-bit symmetric key (hex file)
  seal <key-file> <in|-> <out>   XChaCha20-Poly1305 encrypt (random nonce)
  open <key-file> <in|-> <out>   decrypt and authenticate
  kem-keygen <seed-out> <pub-out>
                                 X25519 + ML-KEM-768 hybrid key pair (hex files)
  kem-encap <pub-file> <ss-out> <ct-out>
                                 encapsulate: shared secret and ciphertext (hex)
  kem-decap <seed-file> <ct-file> <ss-out>
                                 decapsulate: shared secret (hex)
  bench [iterations]             quick timings of the main operations (default 100)
  help                           this message

Output files are created new and never overwritten.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("tpt-crypto: {msg}");
            2
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> Result<i32, String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        println!("{USAGE}");
        return Ok(2);
    };
    let rest = &args[1..];
    match (cmd, rest) {
        ("help" | "--help" | "-h", _) => {
            println!("{USAGE}");
            Ok(0)
        }
        ("selftest", []) => {
            tpt_crypto::selftest::run().map_err(|e| format!("self-test failed: {e:?}"))?;
            println!("selftest: OK");
            Ok(0)
        }
        ("hash", [input]) => {
            let digest = easy::hash(&read_input(input)?);
            println!("{}", to_hex(&digest));
            Ok(0)
        }
        ("random", [n]) => {
            let n: usize = n.parse().map_err(|_| format!("not a byte count: {n}"))?;
            let bytes = easy::random_bytes(n).map_err(|e| format!("rng: {e:?}"))?;
            println!("{}", to_hex(&bytes));
            Ok(0)
        }
        ("sign-keygen", [seed_out, pub_out]) => {
            let seed = easy::ed25519_generate().map_err(|e| format!("rng: {e:?}"))?;
            let public = easy::ed25519_public_key(seed.expose_secret());
            write_secret_text_new(seed_out, &to_hex(seed.expose_secret()))?;
            write_text_new(pub_out, &to_hex(&public))?;
            println!("wrote {seed_out} (secret) and {pub_out}");
            Ok(0)
        }
        ("sign", [seed_file, input, sig_out]) => {
            let seed: [u8; ed25519::SEED_LEN] = read_hex_key(seed_file)?;
            let sig = easy::sign(&seed, &read_input(input)?);
            write_text_new(sig_out, &to_hex(&sig))?;
            println!("wrote {sig_out}");
            Ok(0)
        }
        ("verify", [pub_file, input, sig_file]) => {
            let public: [u8; ed25519::PUBLIC_KEY_LEN] = read_hex_key(pub_file)?;
            let sig: [u8; ed25519::SIGNATURE_LEN] = read_hex_key(sig_file)?;
            match easy::verify(&public, &read_input(input)?, &sig) {
                Ok(()) => {
                    println!("OK");
                    Ok(0)
                }
                Err(_) => {
                    println!("FAIL");
                    Ok(1)
                }
            }
        }
        ("seal-keygen", [key_out]) => {
            let key = easy::generate_key().map_err(|e| format!("rng: {e:?}"))?;
            write_secret_text_new(key_out, &to_hex(key.expose_secret()))?;
            println!("wrote {key_out} (secret)");
            Ok(0)
        }
        ("seal", [key_file, input, out]) => {
            let key: [u8; easy::KEY_LEN] = read_hex_key(key_file)?;
            let sealed =
                easy::seal(&key, &read_input(input)?, b"").map_err(|e| format!("seal: {e:?}"))?;
            write_new(out, &sealed)?;
            println!("wrote {out}");
            Ok(0)
        }
        ("open", [key_file, input, out]) => {
            let key: [u8; easy::KEY_LEN] = read_hex_key(key_file)?;
            match easy::open(&key, &read_input(input)?, b"") {
                Ok(plain) => {
                    write_new(out, &plain)?;
                    println!("wrote {out}");
                    Ok(0)
                }
                Err(_) => {
                    println!("FAIL: authentication failed");
                    Ok(1)
                }
            }
        }
        ("kem-keygen", [seed_out, pub_out]) => {
            let seed = easy::random_bytes(xwing::SEED_LEN).map_err(|e| format!("rng: {e:?}"))?;
            let mut seed_arr = [0u8; xwing::SEED_LEN];
            seed_arr.copy_from_slice(&seed);
            let (public, _sk) = xwing::keygen_seed(&seed_arr);
            write_secret_text_new(seed_out, &to_hex(&seed_arr))?;
            write_text_new(pub_out, &to_hex(&public.0))?;
            println!("wrote {seed_out} (secret) and {pub_out}");
            Ok(0)
        }
        ("kem-encap", [pub_file, ss_out, ct_out]) => {
            let public = xwing::PublicKey(read_hex_key::<{ xwing::PUBLIC_KEY_LEN }>(pub_file)?);
            let (ss, ct) = xwing::encapsulate(&public, &mut OsRng)
                .map_err(|e| format!("encapsulate: {e:?}"))?;
            write_secret_text_new(ss_out, &to_hex(&ss))?;
            write_text_new(ct_out, &to_hex(&ct))?;
            println!("wrote {ss_out} (secret) and {ct_out}");
            Ok(0)
        }
        ("kem-decap", [seed_file, ct_file, ss_out]) => {
            let seed: [u8; xwing::SEED_LEN] = read_hex_key(seed_file)?;
            let ct: [u8; xwing::CIPHERTEXT_LEN] = read_hex_key(ct_file)?;
            let sk = xwing::SecretKey::from_seed(seed);
            match xwing::decapsulate(&sk, &ct) {
                Ok(ss) => {
                    write_secret_text_new(ss_out, &to_hex(&ss))?;
                    println!("wrote {ss_out} (secret)");
                    Ok(0)
                }
                Err(_) => {
                    println!("FAIL: ciphertext rejected");
                    Ok(1)
                }
            }
        }
        ("bench", []) => bench(100),
        ("bench", [n]) => {
            let n: usize = n
                .parse()
                .map_err(|_| format!("not an iteration count: {n}"))?;
            if n == 0 {
                return Err("iteration count must be at least 1".into());
            }
            bench(n)
        }
        _ => {
            eprintln!("{USAGE}");
            Err(format!("unknown or malformed command: {cmd}"))
        }
    }
}

/// Quick timing of the main operations: mean time per call over `n` iterations.
/// This is a sanity check, not a benchmark. Use `benches/` (criterion) for
/// measurements that need to be compared.
fn bench(n: usize) -> Result<i32, String> {
    use std::hint::black_box;
    use std::time::Instant;

    let msg = vec![0x5au8; 1024];
    let seed = [0x11u8; 32];
    let key = [0x22u8; easy::KEY_LEN];

    let mut rows: Vec<(&str, f64)> = Vec::new();
    let mut time = |name: &'static str, f: &mut dyn FnMut()| {
        let start = Instant::now();
        for _ in 0..n {
            f();
        }
        let per_op = start.elapsed().as_secs_f64() * 1e6 / n as f64;
        rows.push((name, per_op));
    };

    time("sha256 (1 KiB)", &mut || {
        black_box(easy::hash(black_box(&msg)));
    });
    time("ed25519 sign (1 KiB)", &mut || {
        black_box(easy::sign(black_box(&seed), black_box(&msg)));
    });
    let public = easy::ed25519_public_key(&seed);
    let sig = easy::sign(&seed, &msg);
    time("ed25519 verify (1 KiB)", &mut || {
        let _ = black_box(easy::verify(
            black_box(&public),
            black_box(&msg),
            black_box(&sig),
        ));
    });
    time("seal (1 KiB)", &mut || {
        let _ = black_box(easy::seal(black_box(&key), black_box(&msg), b""));
    });
    time("x-wing keygen", &mut || {
        black_box(xwing::keygen_seed(black_box(&seed)));
    });
    let (pk, sk) = xwing::keygen_seed(&seed);
    time("x-wing encapsulate", &mut || {
        let _ = black_box(xwing::encapsulate(black_box(&pk), &mut OsRng));
    });
    let (_, ct) = xwing::encapsulate(&pk, &mut OsRng).map_err(|e| format!("encapsulate: {e:?}"))?;
    time("x-wing decapsulate", &mut || {
        let _ = black_box(xwing::decapsulate(black_box(&sk), black_box(&ct)));
    });

    println!("{:<22} {:>12}", "operation", "us/op");
    for (name, us) in rows {
        println!("{name:<22} {us:>12.2}");
    }
    println!("({n} iterations each; debug or release build changes these numbers a lot)");
    Ok(0)
}

/// Read a file, or all of stdin for `-`.
fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("stdin: {e:?}"))?;
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e:?}"))
}

/// Read a hex key file into a fixed-size array.
fn read_hex_key<const N: usize>(path: &str) -> Result<[u8; N], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e:?}"))?;
    let bytes = from_hex(text.trim()).ok_or_else(|| format!("{path}: not hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{path}: expected {N} bytes, found {}", bytes.len()))
}

/// Create a new file and write `data` to it exactly. Refuses to overwrite.
fn write_new(path: &str, data: impl AsRef<[u8]>) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{path}: {e:?}"))?;
    f.write_all(data.as_ref())
        .map_err(|e| format!("{path}: {e:?}"))
}

/// Hex text output (public key, signature, key file): `hex` plus a newline.
fn write_text_new(path: &str, hex: &str) -> Result<(), String> {
    write_new(path, format!("{hex}\n"))
}

/// Like [`write_text_new`], but on Unix the file is created readable only by its owner.
fn write_secret_text_new(path: &str, hex: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{path}: {e:?}"))?;
        f.write_all(format!("{hex}\n").as_bytes())
            .map_err(|e| format!("{path}: {e:?}"))
    }
    #[cfg(not(unix))]
    {
        write_text_new(path, hex)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00, 0x7f, 0x80, 0xff];
        assert_eq!(to_hex(&bytes), "007f80ff");
        assert_eq!(from_hex("007f80ff").unwrap(), bytes);
        assert_eq!(from_hex("007F80FF").unwrap(), bytes);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }
}
