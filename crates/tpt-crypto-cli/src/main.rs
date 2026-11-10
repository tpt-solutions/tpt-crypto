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
        _ => {
            eprintln!("{USAGE}");
            Err(format!("unknown or malformed command: {cmd}"))
        }
    }
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
