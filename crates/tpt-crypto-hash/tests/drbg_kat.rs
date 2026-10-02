//! HMAC-DRBG (SP 800-90A) ACVP known-answer tests
//! (`tests/kat/hmac_drbg_acvp.txt`, distilled — see `tests/kat/PROVENANCE.md`).
//!
//! Covers the SHA2-256 ACVP groups (both prediction-resistance and not, both
//! returned-bits lengths). Each record instantiates from
//! `entropy ‖ nonce` + personalization, replays the reseed/generate op list
//! in order, and must reproduce the ACVP `returned` bytes exactly.

use tpt_crypto_core::DrbgCore;
use tpt_crypto_hash::HmacDrbg;

const VECTORS: &str = include_str!("kat/hmac_drbg_acvp.txt");

/// One `[section]` block of `key = value` fields.
struct Record {
    kind: String,
    fields: Vec<(String, String)>,
}

fn parse(text: &str) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Record {
                kind: name.to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        let (k, v) = line.split_once('=').expect("`key = value` line");
        out.last_mut()
            .expect("field inside a section")
            .fields
            .push((k.trim().to_string(), v.trim().to_string()));
    }
    out
}

fn f<'a>(r: &'a Record, key: &str) -> &'a str {
    r.fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn hmac_drbg_sha2_256_acvp() {
    let records = parse(VECTORS);
    let kats: Vec<&Record> = records.iter().filter(|r| r.kind == "kat").collect();
    assert_eq!(kats.len(), 16, "expected 16 HMAC-DRBG records");

    for r in kats {
        let count = f(r, "count");
        let pr = f(r, "pr") == "true";
        let ret_len: usize = f(r, "ret_len").parse().expect("ret_len");
        let mut seed = unhex(f(r, "entropy"));
        seed.extend_from_slice(&unhex(f(r, "nonce")));
        let pers = unhex(f(r, "pers"));

        let mut drbg = HmacDrbg::<tpt_crypto_hash::sha2::Sha256, 64, 32>::new(&pers, &seed);

        // Replay the op list in field order: `op<i>_(reseed|generate)_ai`,
        // with an optional `op<i>_entropy` (reseed / pr-generate). The ACVP
        // `returned` bits are the output of the LAST generate call.
        let mut ops: Vec<(usize, bool, String)> = r
            .fields
            .iter()
            .filter_map(|(k, v)| {
                let rest = k.strip_prefix("op")?;
                let idx_end = rest.find('_')?;
                let idx: usize = rest[..idx_end].parse().ok()?;
                let kind = rest[idx_end + 1..].strip_suffix("_ai")?;
                Some((idx, kind == "generate", v.clone()))
            })
            .collect();
        ops.sort_by_key(|(i, _, _)| *i);
        let gens = ops.iter().filter(|(_, g, _)| *g).count();
        assert!(gens > 0, "record has no generate op");
        // ACVP semantics (pinned against the ACVP-Server expected results):
        // - PR groups: each Generate is preceded by
        //   Reseed(op.entropy, op.ai), and the Generate call itself runs
        //   WITHOUT additional input (the reseed consumed it).
        // - non-PR groups: the explicit reSeed op is
        //   Reseed(op.entropy, op.ai); each Generate runs with its OWN
        //   op.ai as additional input.
        // `returned` is the last Generate call's full `ret_len` output.
        let mut out = None;

        for (idx, is_generate, ai) in ops {
            let ai_bytes = if ai == "-" { Vec::new() } else { unhex(&ai) };
            let ent_key = format!("op{idx}_entropy");
            let ent_field = f(r, &ent_key);
            let entropy = if ent_field.is_empty() {
                Vec::new()
            } else {
                unhex(ent_field)
            };
            if !is_generate {
                drbg.reseed(&entropy, &ai_bytes);
                continue;
            }
            if pr {
                drbg.reseed(&entropy, &ai_bytes);
                let mut buf = vec![0u8; ret_len];
                drbg.generate(&mut buf, &[]).expect("generate succeeds");
                out = Some(buf);
            } else {
                let mut buf = vec![0u8; ret_len];
                drbg.generate(&mut buf, &ai_bytes)
                    .expect("generate succeeds");
                out = Some(buf);
            }
        }
        let want = unhex(f(r, "returned"));
        assert_eq!(
            out.as_deref(),
            Some(want.as_slice()),
            "[count {count}] returned bits mismatch"
        );
    }
}
