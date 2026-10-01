//! SLH-DSA (FIPS 205) — stateless hash-based signatures (SPHINCS+-a).
//!
//! The construction: FORS over the message digest, certified by a hypertree
//! of `d` XMSS layers of WOTS+ one-time signatures. All hashing goes through
//! the FIPS 205 tweakable hashes (`H_msg`, `PRF`, `PRF_msg`, `F`, `H`, `T_l`)
//! built on SHAKE256 or SHA-2 (§11.2/§11.3).
//!
//! Parameter sets follow FIPS 205 Table 2: `n ∈ {16, 24, 32}`,
//! `h ∈ {63, 66, 64, 68}`, `d` layers, FORS height `a`/trees `k`. The twelve
//! combinations (two hash families × three security levels × {s, f}) cover
//! security categories 1–5.
//!
//! Signing is deterministic by default (`opt_rand = PK.seed`); hedged signing
//! with a caller-supplied `opt_rand` is available via [`sign_hedged`]. The
//! message is formatted as `M' = dom ‖ |ctx| ‖ ctx ‖ M` with `dom = 0` (pure)
//! per §9.2.

use alloc::vec::Vec;

use tpt_crypto_hash::mac::Hmac;
use tpt_crypto_hash::sha2::{Sha256, Sha512};
use tpt_crypto_hash::sha3::Shake256;
use tpt_crypto_hash::{Hasher, Xof};

use crate::{Error, Result};

// ── Parameter sets ───────────────────────────────────────────────────────────

/// SLH-DSA parameter set identifier (FIPS 205 Table 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlhDsaParam {
    /// SHA2-128f (fast, category 1).
    Sha2_128f,
    /// SHA2-128s (small, category 1).
    Sha2_128s,
    /// SHA2-192f (fast, category 3).
    Sha2_192f,
    /// SHA2-192s (small, category 3).
    Sha2_192s,
    /// SHA2-256f (fast, category 5).
    Sha2_256f,
    /// SHA2-256s (small, category 5).
    Sha2_256s,
    /// SHAKE-128f (fast, category 1).
    Shake128f,
    /// SHAKE-128s (small, category 1).
    Shake128s,
    /// SHAKE-192f (fast, category 3).
    Shake192f,
    /// SHAKE-192s (small, category 3).
    Shake192s,
    /// SHAKE-256f (fast, category 5).
    Shake256f,
    /// SHAKE-256s (small, category 5).
    Shake256s,
}

/// Decoded parameter table (FIPS 205 Table 2 rows).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Params {
    /// Hash output / seed length in bytes.
    pub n: usize,
    /// Total tree height.
    pub h: usize,
    /// Number of XMSS layers.
    pub d: usize,
    /// XMSS subtree height (`h / d`).
    pub h_m: usize,
    /// FORS tree height.
    pub a: usize,
    /// Number of FORS trees.
    pub k: usize,
    /// FORS message-digest length in bytes (`⌈k·a/8⌉`).
    pub md_bytes: usize,
    /// Bytes encoding the subtree index in the digest.
    pub tree_bytes: usize,
    /// Bytes encoding the leaf index in the digest.
    pub leaf_bytes: usize,
    /// WOTS+ chain count (`len₁ + len₂`).
    pub wts_len: usize,
    /// Encoded signature length in bytes.
    pub sig_len: usize,
    /// `true` for the SHAKE family; `false` for SHA-2.
    pub shake: bool,
    /// SHA-2 only: `true` for the 192/256 families (SHA-512 for
    /// `H_msg`/`H`/`T_l`/PRF_msg per FIPS 205 §11.3), `false` for 128.
    pub sha512: bool,
}

const fn ceil_div(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

const fn wots_len2(n: usize) -> usize {
    // len₂ = ⌊log₂(len₁·(w−1)) / lg_w⌋ + 1 with len₁ = 2n, w = 16.
    let len1 = 2 * n;
    let mut bits = 0usize;
    let mut v = len1 * 15;
    while v > 0 {
        bits += 1;
        v >>= 1;
    }
    bits / 4 + 1
}

const fn params_row(n: usize, h: usize, d: usize, a: usize, k: usize, shake: bool) -> Params {
    let h_m = h / d;
    let md_bytes = ceil_div(k * a, 8);
    let tree_bytes = ceil_div(h - h_m, 8);
    let leaf_bytes = ceil_div(h_m, 8);
    let len1 = 2 * n;
    let wts_len = len1 + wots_len2(n);
    let sig_len = (1 + k * (a + 1) + h + d * wts_len) * n;
    Params {
        n,
        h,
        d,
        h_m,
        a,
        k,
        md_bytes,
        tree_bytes,
        leaf_bytes,
        wts_len,
        sig_len,
        shake,
        sha512: !shake && n >= 24,
    }
}

impl SlhDsaParam {
    pub(crate) fn params(&self) -> Params {
        let (row, shake) = match self {
            SlhDsaParam::Sha2_128f => ((16, 66, 22, 6, 33), false),
            SlhDsaParam::Sha2_128s => ((16, 63, 7, 12, 14), false),
            SlhDsaParam::Sha2_192f => ((24, 66, 22, 8, 33), false),
            SlhDsaParam::Sha2_192s => ((24, 63, 7, 14, 17), false),
            SlhDsaParam::Sha2_256f => ((32, 68, 17, 9, 35), false),
            SlhDsaParam::Sha2_256s => ((32, 64, 8, 14, 22), false),
            SlhDsaParam::Shake128f => ((16, 66, 22, 6, 33), true),
            SlhDsaParam::Shake128s => ((16, 63, 7, 12, 14), true),
            SlhDsaParam::Shake192f => ((24, 66, 22, 8, 33), true),
            SlhDsaParam::Shake192s => ((24, 63, 7, 14, 17), true),
            SlhDsaParam::Shake256f => ((32, 68, 17, 9, 35), true),
            SlhDsaParam::Shake256s => ((32, 64, 8, 14, 22), true),
        };
        params_row(row.0, row.1, row.2, row.3, row.4, shake)
    }

    /// Encoded public-key length (`2n`).
    #[must_use]
    pub fn pk_len(&self) -> usize {
        2 * self.params().n
    }

    /// Encoded secret-key length (`4n`).
    #[must_use]
    pub fn sk_len(&self) -> usize {
        4 * self.params().n
    }

    /// Encoded signature length.
    #[must_use]
    pub fn sig_len(&self) -> usize {
        self.params().sig_len
    }
}

// ── Key/signature types ──────────────────────────────────────────────────────

/// An SLH-DSA public key: `PK.seed ‖ PK.root` (`2n` bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Encoded public-key bytes.
    pub bytes: Vec<u8>,
}

/// An SLH-DSA secret key: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` (`4n` bytes).
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// Encoded secret-key bytes.
    pub bytes: Vec<u8>,
}

/// An SLH-DSA signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Encoded signature bytes.
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Parse a public key of `param`.
    pub fn from_bytes(param: SlhDsaParam, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != param.pk_len() {
            return Err(Error::InvalidLength);
        }
        Ok(PublicKey {
            bytes: bytes.to_vec(),
        })
    }

    /// Borrow the encoded public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SecretKey {
    /// Parse a secret key of `param`.
    pub fn from_bytes(param: SlhDsaParam, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != param.sk_len() {
            return Err(Error::InvalidLength);
        }
        Ok(SecretKey {
            bytes: bytes.to_vec(),
        })
    }

    /// Borrow the encoded secret key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Signature {
    /// Parse a signature of `param`.
    pub fn from_bytes(param: SlhDsaParam, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != param.sig_len() {
            return Err(Error::InvalidLength);
        }
        Ok(Signature {
            bytes: bytes.to_vec(),
        })
    }

    /// Borrow the encoded signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ── ADRS (§9.1) ──────────────────────────────────────────────────────────────

const TYPE_WOTS_HASH: u32 = 0;
const TYPE_WOTS_PK: u32 = 1;
const TYPE_TREE: u32 = 2;
const TYPE_FORS_TREE: u32 = 3;
const TYPE_FORS_ROOTS: u32 = 4;
const TYPE_WOTS_PRF: u32 = 5;
const TYPE_FORS_PRF: u32 = 6;

/// The 32-byte address register.
#[derive(Clone, Copy)]
struct Adrs([u8; 32]);

impl Adrs {
    fn new(layer: u32, tree: u64) -> Self {
        let mut a = [0u8; 32];
        a[0..4].copy_from_slice(&layer.to_be_bytes());
        // 12-byte tree address: 4 zero bytes above the 8-byte value.
        a[8..16].copy_from_slice(&tree.to_be_bytes());
        Adrs(a)
    }

    fn with_type(&mut self, ty: u32) -> &mut Self {
        self.0[16..20].copy_from_slice(&ty.to_be_bytes());
        // The trailing 12 bytes are zeroed on type change (the OTS/TREE
        // encodings overlap).
        self.0[20..32].fill(0);
        self
    }

    fn set_keypair(&mut self, kp: u32) {
        self.0[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    fn set_chain(&mut self, chain: u32) {
        self.0[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    fn set_hash(&mut self, hash: u32) {
        self.0[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    fn set_height(&mut self, height: u32) {
        self.0[24..28].copy_from_slice(&height.to_be_bytes());
    }

    fn set_index(&mut self, index: u32) {
        self.0[28..32].copy_from_slice(&index.to_be_bytes());
    }

    fn keypair(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
    }

    /// `ADRS_C` — the 22-byte compressed form used by the SHA-2 hashes
    /// (byte 3 of the layer, bytes 8..16 of the tree, bytes 19..32).
    fn compressed(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.0[3];
        out[1..9].copy_from_slice(&self.0[8..16]);
        out[9..22].copy_from_slice(&self.0[19..32]);
        out
    }
}

// ── Tweakable hashes (§11) ───────────────────────────────────────────────────

fn shake256_n(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::new();
    for p in parts {
        x.update(p);
    }
    x.squeeze(out);
}

fn hmac_sha(out: &mut [u8], key: &[u8], msg: &[u8], sha512: bool) {
    if sha512 {
        let mut m = Hmac::<Sha512, 128, 64>::new(key);
        m.update(msg);
        let d = m.finalize();
        let n = out.len();
        out.copy_from_slice(&d[..n]);
    } else {
        let mut m = Hmac::<Sha256, 64, 32>::new(key);
        m.update(msg);
        let d = m.finalize();
        let n = out.len();
        out.copy_from_slice(&d[..n]);
    }
}

fn sha_x(out: &mut [u8], parts: &[&[u8]], sha512: bool) {
    if sha512 {
        let mut h = Sha512::new();
        for p in parts {
            h.update(p);
        }
        let d = h.finalize();
        let n = out.len();
        out.copy_from_slice(&d[..n]);
    } else {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let d = h.finalize();
        let n = out.len();
        out.copy_from_slice(&d[..n]);
    }
}

fn mgf1(out: &mut [u8], seed: &[u8], sha512: bool) {
    let mut counter = 0u32;
    let mut pos = 0usize;
    while pos < out.len() {
        if sha512 {
            let mut h = Sha512::new();
            h.update(seed);
            h.update(&counter.to_be_bytes());
            let d = h.finalize();
            let take = (out.len() - pos).min(d.len());
            out[pos..pos + take].copy_from_slice(&d[..take]);
            pos += take;
        } else {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(&counter.to_be_bytes());
            let d = h.finalize();
            let take = (out.len() - pos).min(d.len());
            out[pos..pos + take].copy_from_slice(&d[..take]);
            pos += take;
        }
        counter += 1;
    }
}

/// `H_msg(R, PK.seed, PK.root, M')` — `md + tree + leaf` bytes of output.
fn h_msg(p: &Params, r: &[u8], pk: &[u8], m_prime: &[u8], out: &mut [u8]) {
    if p.shake {
        shake256_n(&[r, &pk[..p.n], &pk[p.n..2 * p.n], m_prime], out);
    } else if p.sha512 {
        let mut inner = [0u8; 64];
        sha_x(
            &mut inner,
            &[r, &pk[..p.n], &pk[p.n..2 * p.n], m_prime],
            true,
        );
        let mut seed = Vec::with_capacity(p.n + 64);
        seed.extend_from_slice(r);
        seed.extend_from_slice(&pk[..p.n]);
        seed.extend_from_slice(&inner);
        mgf1(out, &seed, true);
    } else {
        let mut inner = [0u8; 32];
        sha_x(
            &mut inner,
            &[r, &pk[..p.n], &pk[p.n..2 * p.n], m_prime],
            false,
        );
        let mut seed = Vec::with_capacity(p.n + 32);
        seed.extend_from_slice(r);
        seed.extend_from_slice(&pk[..p.n]);
        seed.extend_from_slice(&inner);
        mgf1(out, &seed, false);
    }
}

/// `PRF(PK.seed, SK.seed, ADRS)` — `n` bytes.
fn prf(p: &Params, pk_seed: &[u8], adrs: &Adrs, sk_seed: &[u8], out: &mut [u8]) {
    if p.shake {
        shake256_n(&[&pk_seed[..p.n], &adrs.0, &sk_seed[..p.n]], out);
    } else {
        let adrs_c = adrs.compressed();
        let zeros = [0u8; 64];
        sha_x(
            out,
            &[
                &pk_seed[..p.n],
                &zeros[..64 - p.n],
                &adrs_c,
                &sk_seed[..p.n],
            ],
            false,
        );
    }
}

/// `PRF_msg(SK.prf, opt_rand, M')` — `n` bytes.
fn prf_msg(p: &Params, sk_prf: &[u8], opt_rand: &[u8], m_prime: &[u8], out: &mut [u8]) {
    if p.shake {
        shake256_n(&[&sk_prf[..p.n], opt_rand, m_prime], out);
    } else {
        let mut buf = Vec::with_capacity(opt_rand.len() + m_prime.len());
        buf.extend_from_slice(opt_rand);
        buf.extend_from_slice(m_prime);
        hmac_sha(out, &sk_prf[..p.n], &buf, p.sha512);
    }
}

/// `F(PK.seed, ADRS, M1)` with `M1` of `n` bytes.
fn thash_f(p: &Params, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], out: &mut [u8]) {
    if p.shake {
        shake256_n(&[&pk_seed[..p.n], &adrs.0, m1], out);
    } else {
        let adrs_c = adrs.compressed();
        let zeros = [0u8; 64];
        sha_x(
            out,
            &[&pk_seed[..p.n], &zeros[..64 - p.n], &adrs_c, m1],
            false,
        );
    }
}

/// `H`/`T_l(PK.seed, ADRS, M2)` with a multi-block `M2` (2n bytes for `H`,
/// `k·n` for `T_l`). SHA-512 for the 192/256 SHA-2 families, SHA-256 for 128.
fn thash_ht(p: &Params, pk_seed: &[u8], adrs: &Adrs, m2: &[u8], out: &mut [u8]) {
    if p.shake {
        shake256_n(&[&pk_seed[..p.n], &adrs.0, m2], out);
    } else if p.sha512 {
        let zeros = [0u8; 128];
        sha_x(
            out,
            &[&pk_seed[..p.n], &zeros[..128 - p.n], &adrs.compressed(), m2],
            true,
        );
    } else {
        let zeros = [0u8; 64];
        sha_x(
            out,
            &[&pk_seed[..p.n], &zeros[..64 - p.n], &adrs.compressed(), m2],
            false,
        );
    }
}

// ── WOTS+ ────────────────────────────────────────────────────────────────────

/// MSB-first base-`2^b` expansion of `data` into `out_len` digits.
fn base_2b(data: &[u8], b: u32, out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut in_pos = 0usize;
    let mut bits = 0u32;
    let mut total = 0u64;
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | u64::from(data[in_pos]);
            in_pos += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) as u32) & ((1 << b) - 1));
    }
    out
}

/// `chain(X, i, s, PK.seed, ADRS)`.
fn chain(
    p: &Params,
    start_state: &[u8],
    start: usize,
    steps: usize,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    let mut input = [0u8; 32];
    let mut state = [0u8; 32];
    input[..p.n].copy_from_slice(&start_state[..p.n]);
    state[..p.n].copy_from_slice(&start_state[..p.n]);
    for j in start..start + steps {
        adrs.set_hash(j as u32);
        input[..p.n].copy_from_slice(&state[..p.n]);
        thash_f(p, pk_seed, adrs, &input[..p.n], &mut state[..p.n]);
    }
    out[..p.n].copy_from_slice(&state[..p.n]);
}

/// `wots_pkGen`: the WOTS+ public key for `keypair`.
fn wots_pk_gen(p: &Params, sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) {
    let kp = adrs.keypair();
    let mut sk_adrs = *adrs;
    sk_adrs.with_type(TYPE_WOTS_PRF);
    sk_adrs.set_keypair(kp);
    let mut tmp = Vec::with_capacity(p.wts_len * p.n);
    let mut chain_adrs = *adrs;
    chain_adrs.with_type(TYPE_WOTS_HASH);
    chain_adrs.set_keypair(kp);
    for i in 0..p.wts_len {
        sk_adrs.set_chain(i as u32);
        let mut sk = [0u8; 32];
        prf(p, pk_seed, &sk_adrs, sk_seed, &mut sk[..p.n]);
        chain_adrs.set_chain(i as u32);
        let mut node = [0u8; 32];
        node[..p.n].copy_from_slice(&sk[..p.n]);
        let mut tmp_in = [0u8; 32];
        tmp_in[..p.n].copy_from_slice(&sk[..p.n]);
        chain(
            p,
            &tmp_in[..p.n],
            0,
            15,
            pk_seed,
            &mut chain_adrs,
            &mut node[..p.n],
        );
        tmp.extend_from_slice(&node[..p.n]);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.with_type(TYPE_WOTS_PK);
    pk_adrs.set_keypair(kp);
    thash_ht(p, pk_seed, &pk_adrs, &tmp, &mut out[..p.n]);
}

/// WOTS message formatting: base-16 digits of `msg` plus the checksum.
fn wots_digits(p: &Params, msg: &[u8]) -> Vec<u32> {
    let len1 = 2 * p.n;
    let mut digits = base_2b(msg, 4, len1);
    let mut csum: u32 = 0;
    for d in digits.iter().take(len1) {
        csum += 15 - d;
    }
    // Left-shift so the base-16 digits of the checksum are MSB-aligned.
    // `len₂·lg_w = 12` bits: left-align the checksum in its 2 bytes.
    let shift = 8 - (3 * 4) % 8;
    let csum = csum << shift;
    let csum_bytes = ceil_div(3 * 4, 8);
    let be = csum.to_be_bytes();
    let start = be.len() - csum_bytes;
    digits.extend(base_2b(&be[start..], 4, 3));
    digits
}

/// `wots_sign`: `len` chain-end values for the base-16 message + checksum.
fn wots_sign(
    p: &Params,
    msg_digits: &[u32],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    let kp = adrs.keypair();
    let mut sk_adrs = *adrs;
    sk_adrs.with_type(TYPE_WOTS_PRF);
    sk_adrs.set_keypair(kp);
    let mut chain_adrs = *adrs;
    chain_adrs.with_type(TYPE_WOTS_HASH);
    chain_adrs.set_keypair(kp);
    let mut node = [0u8; 32];
    let mut tmp_in = [0u8; 32];
    for i in 0..p.wts_len {
        sk_adrs.set_chain(i as u32);
        let mut sk = [0u8; 32];
        prf(p, pk_seed, &sk_adrs, sk_seed, &mut sk[..p.n]);
        chain_adrs.set_chain(i as u32);
        node[..p.n].copy_from_slice(&sk[..p.n]);
        tmp_in[..p.n].copy_from_slice(&sk[..p.n]);
        chain(
            p,
            &tmp_in[..p.n],
            0,
            msg_digits[i] as usize,
            pk_seed,
            &mut chain_adrs,
            &mut node[..p.n],
        );
        out[i * p.n..(i + 1) * p.n].copy_from_slice(&node[..p.n]);
    }
}

/// `wots_pkFromSig`: re-derive the WOTS+ public key from a signature.
fn wots_pk_from_sig(
    p: &Params,
    sig: &[u8],
    msg_digits: &[u32],
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    let kp = adrs.keypair();
    let mut tmp = Vec::with_capacity(p.wts_len * p.n);
    let mut chain_adrs = *adrs;
    chain_adrs.with_type(TYPE_WOTS_HASH);
    chain_adrs.set_keypair(kp);
    let mut node = [0u8; 32];
    let mut tmp_in = [0u8; 32];
    for i in 0..p.wts_len {
        chain_adrs.set_chain(i as u32);
        node[..p.n].copy_from_slice(&sig[i * p.n..(i + 1) * p.n]);
        tmp_in[..p.n].copy_from_slice(&node[..p.n]);
        chain(
            p,
            &tmp_in[..p.n],
            msg_digits[i] as usize,
            (15 - msg_digits[i]) as usize,
            pk_seed,
            &mut chain_adrs,
            &mut node[..p.n],
        );
        tmp.extend_from_slice(&node[..p.n]);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.with_type(TYPE_WOTS_PK);
    pk_adrs.set_keypair(kp);
    thash_ht(p, pk_seed, &pk_adrs, &tmp, &mut out[..p.n]);
}

// ── XMSS ─────────────────────────────────────────────────────────────────────

/// `xmss_node`: the root of the subtree of height `dep` rooted at `cur`.
fn xmss_node(
    p: &Params,
    sk_seed: &[u8],
    cur: u32,
    dep: usize,
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    if dep == 0 {
        let mut a = *adrs;
        a.with_type(TYPE_WOTS_HASH);
        a.set_keypair(cur);
        wots_pk_gen(p, sk_seed, pk_seed, &a, out);
    } else {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        xmss_node(
            p,
            sk_seed,
            2 * cur,
            dep - 1,
            pk_seed,
            adrs,
            &mut left[..p.n],
        );
        xmss_node(
            p,
            sk_seed,
            2 * cur + 1,
            dep - 1,
            pk_seed,
            adrs,
            &mut right[..p.n],
        );
        let mut a = *adrs;
        a.with_type(TYPE_TREE);
        a.set_height(dep as u32);
        a.set_index(cur);
        let mut buf = [0u8; 64];
        buf[..p.n].copy_from_slice(&left[..p.n]);
        buf[p.n..2 * p.n].copy_from_slice(&right[..p.n]);
        thash_ht(p, pk_seed, &a, &buf[..2 * p.n], out);
    }
}

/// `xmss_sign`: WOTS signature plus the `h_m`-node authentication path.
fn xmss_sign(
    p: &Params,
    msg: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    let mut a = *adrs;
    a.with_type(TYPE_WOTS_HASH);
    a.set_keypair(idx);
    wots_sign(
        p,
        &wots_digits(p, msg),
        sk_seed,
        pk_seed,
        &a,
        &mut out[..p.wts_len * p.n],
    );
    let mut offset = p.wts_len * p.n;
    for j in 0..p.h_m {
        let k = (idx >> j) ^ 1;
        xmss_node(
            p,
            sk_seed,
            k,
            j,
            pk_seed,
            adrs,
            &mut out[offset..offset + p.n],
        );
        offset += p.n;
    }
}

/// `xmss_pkFromSig`: re-derive the XMSS root from a signature.
fn xmss_pk_from_sig(
    p: &Params,
    idx: u32,
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    let mut a = *adrs;
    a.with_type(TYPE_WOTS_HASH);
    a.set_keypair(idx);
    let mut node = [0u8; 32];
    wots_pk_from_sig(p, sig, &wots_digits(p, msg), pk_seed, &a, &mut node[..p.n]);
    let mut a = *adrs;
    a.with_type(TYPE_TREE);
    a.set_index(idx);
    for k in 0..p.h_m {
        a.set_height((k + 1) as u32);
        let auth = &sig[p.wts_len * p.n + k * p.n..p.wts_len * p.n + (k + 1) * p.n];
        if (idx >> k) & 1 == 0 {
            a.set_index(idx >> (k + 1));
            let mut buf = [0u8; 64];
            buf[..p.n].copy_from_slice(&node[..p.n]);
            buf[p.n..2 * p.n].copy_from_slice(auth);
            thash_ht(p, pk_seed, &a, &buf[..2 * p.n], &mut node[..p.n]);
        } else {
            a.set_index(((idx >> k) - 1) / 2);
            let mut buf = [0u8; 64];
            buf[..p.n].copy_from_slice(auth);
            buf[p.n..2 * p.n].copy_from_slice(&node[..p.n]);
            thash_ht(p, pk_seed, &a, &buf[..2 * p.n], &mut node[..p.n]);
        }
    }
    out[..p.n].copy_from_slice(&node[..p.n]);
}

// ── FORS ─────────────────────────────────────────────────────────────────────

/// `fors_sign`: `k` secret-leaf + auth-path pairs over `a`-height trees.
fn fors_sign(p: &Params, md: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs, out: &mut [u8]) {
    let indices = base_2b(md, p.a as u32, p.k);
    let kp = adrs.keypair();
    let mut sk_adrs = *adrs;
    sk_adrs.with_type(TYPE_FORS_PRF);
    sk_adrs.set_keypair(kp);
    let mut node_adrs = *adrs;
    node_adrs.with_type(TYPE_FORS_TREE);
    node_adrs.set_keypair(kp);
    let mut node = [0u8; 32];
    for i in 0..p.k {
        let leaf = i * (1 << p.a) + indices[i] as usize;
        sk_adrs.set_index(leaf as u32);
        prf(p, pk_seed, &sk_adrs, sk_seed, &mut node[..p.n]);
        let sk = node[..p.n].to_vec();
        node_adrs.set_height(0);
        node_adrs.set_index(leaf as u32);
        thash_f(p, pk_seed, &node_adrs, &sk, &mut node[..p.n]);
        out[i * (p.a + 1) * p.n..i * (p.a + 1) * p.n + p.n].copy_from_slice(&sk);
        for j in 0..p.a {
            let s = (indices[i] >> j) ^ 1;
            fors_node(
                p,
                sk_seed,
                i * (1 << (p.a - j)) + s as usize,
                j,
                pk_seed,
                &node_adrs,
                &mut out[(i * (p.a + 1) + 1 + j) * p.n..(i * (p.a + 1) + 2 + j) * p.n],
            );
        }
    }
}

/// `fors_node`: the node at height `dep`, index `cur` of the FORS forest.
fn fors_node(
    p: &Params,
    sk_seed: &[u8],
    cur: usize,
    dep: usize,
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    if dep == 0 {
        let mut sk_adrs = *adrs;
        sk_adrs.with_type(TYPE_FORS_PRF);
        sk_adrs.set_keypair(adrs.keypair());
        sk_adrs.set_index(cur as u32);
        prf(p, pk_seed, &sk_adrs, sk_seed, out);
        let sk = out[..p.n].to_vec();
        let mut a = *adrs;
        a.with_type(TYPE_FORS_TREE);
        // The keypair field persists across type changes in the reference
        // (only height/index are overwritten for tree hashing).
        a.set_keypair(adrs.keypair());
        a.set_height(0);
        a.set_index(cur as u32);
        thash_f(p, pk_seed, &a, &sk, out);
    } else {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        fors_node(
            p,
            sk_seed,
            2 * cur,
            dep - 1,
            pk_seed,
            adrs,
            &mut left[..p.n],
        );
        fors_node(
            p,
            sk_seed,
            2 * cur + 1,
            dep - 1,
            pk_seed,
            adrs,
            &mut right[..p.n],
        );
        let mut a = *adrs;
        a.with_type(TYPE_FORS_TREE);
        // Keypair persists across type changes in the reference.
        a.set_keypair(adrs.keypair());
        a.set_height(dep as u32);
        a.set_index(cur as u32);
        let mut buf = [0u8; 64];
        buf[..p.n].copy_from_slice(&left[..p.n]);
        buf[p.n..2 * p.n].copy_from_slice(&right[..p.n]);
        thash_ht(p, pk_seed, &a, &buf[..2 * p.n], out);
    }
}

/// `fors_pkFromSig`: recover the FORS public key from a signature.
fn fors_pk_from_sig(
    p: &Params,
    sig: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    out: &mut [u8],
) {
    let indices = base_2b(md, p.a as u32, p.k);
    let kp = adrs.keypair();
    let mut node_adrs = *adrs;
    node_adrs.with_type(TYPE_FORS_TREE);
    node_adrs.set_keypair(kp);
    let mut root = Vec::with_capacity(p.k * p.n);
    let mut node = [0u8; 32];
    for i in 0..p.k {
        let sk = &sig[i * (p.a + 1) * p.n..i * (p.a + 1) * p.n + p.n];
        node_adrs.set_height(0);
        node_adrs.set_index((i * (1 << p.a) + indices[i] as usize) as u32);
        thash_f(p, pk_seed, &node_adrs, sk, &mut node[..p.n]);
        let auth_base = (i * (p.a + 1) + 1) * p.n;
        for j in 0..p.a {
            node_adrs.set_height((j + 1) as u32);
            let auth = &sig[auth_base + j * p.n..auth_base + (j + 1) * p.n];
            if (indices[i] >> j) & 1 == 0 {
                node_adrs.set_index(node_adrs_index(&node_adrs) >> 1);
                let mut buf = [0u8; 64];
                buf[..p.n].copy_from_slice(&node[..p.n]);
                buf[p.n..2 * p.n].copy_from_slice(auth);
                thash_ht(p, pk_seed, &node_adrs, &buf[..2 * p.n], &mut node[..p.n]);
            } else {
                node_adrs.set_index((node_adrs_index(&node_adrs) - 1) / 2);
                let mut buf = [0u8; 64];
                buf[..p.n].copy_from_slice(auth);
                buf[p.n..2 * p.n].copy_from_slice(&node[..p.n]);
                thash_ht(p, pk_seed, &node_adrs, &buf[..2 * p.n], &mut node[..p.n]);
            }
        }
        root.extend_from_slice(&node[..p.n]);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.with_type(TYPE_FORS_ROOTS);
    pk_adrs.set_keypair(kp);
    thash_ht(p, pk_seed, &pk_adrs, &root, out);
}

fn node_adrs_index(adrs: &Adrs) -> u32 {
    u32::from_be_bytes([adrs.0[28], adrs.0[29], adrs.0[30], adrs.0[31]])
}

// ── Hypertree ────────────────────────────────────────────────────────────────

fn xmss_sig_len(p: &Params) -> usize {
    (p.h_m + p.wts_len) * p.n
}

/// `ht_sign`: `d` chained XMSS signatures over `root` at `(tree, leaf)`.
fn ht_sign(
    p: &Params,
    root: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
    out: &mut [u8],
) {
    let xsig = xmss_sig_len(p);
    let mut adrs = Adrs::new(0, tree);
    xmss_sign(p, root, sk_seed, leaf, pk_seed, &adrs, &mut out[..xsig]);
    let mut layer_root = [0u8; 32];
    xmss_pk_from_sig(
        p,
        leaf,
        &out[..xsig],
        root,
        pk_seed,
        &adrs,
        &mut layer_root[..p.n],
    );
    for j in 1..p.d {
        leaf = (tree & ((1 << p.h_m) - 1) as u64) as u32;
        tree >>= p.h_m;
        adrs = Adrs::new(j as u32, tree);
        let msg_copy = layer_root;
        xmss_sign(
            p,
            &msg_copy[..p.n],
            sk_seed,
            leaf,
            pk_seed,
            &adrs,
            &mut out[j * xsig..(j + 1) * xsig],
        );
        if j < p.d - 1 {
            let mut next = [0u8; 32];
            xmss_pk_from_sig(
                p,
                leaf,
                &out[j * xsig..(j + 1) * xsig],
                &msg_copy[..p.n],
                pk_seed,
                &adrs,
                &mut next[..p.n],
            );
            layer_root[..p.n].copy_from_slice(&next[..p.n]);
        }
    }
}

/// `ht_verify`: verify the `d` chained XMSS signatures.
fn ht_verify(
    p: &Params,
    root: &[u8],
    sig: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
    pk_root: &[u8],
) -> bool {
    let xsig = xmss_sig_len(p);
    let mut adrs = Adrs::new(0, tree);
    let mut node = [0u8; 32];
    xmss_pk_from_sig(
        p,
        leaf,
        &sig[..xsig],
        root,
        pk_seed,
        &adrs,
        &mut node[..p.n],
    );
    for j in 1..p.d {
        leaf = (tree & ((1 << p.h_m) - 1) as u64) as u32;
        tree >>= p.h_m;
        adrs = Adrs::new(j as u32, tree);
        let msg_copy = node;
        let mut next = [0u8; 32];
        xmss_pk_from_sig(
            p,
            leaf,
            &sig[j * xsig..(j + 1) * xsig],
            &msg_copy[..p.n],
            pk_seed,
            &adrs,
            &mut next[..p.n],
        );
        node[..p.n].copy_from_slice(&next[..p.n]);
    }
    node[..p.n] == pk_root[..p.n]
}

// ── Message formatting (§9.2) and digest split ───────────────────────────────

fn format_message(ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    if ctx.len() > 255 {
        return Err(Error::InvalidLength);
    }
    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());
    m.push(0u8); // dom = 0 (pure)
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    Ok(m)
}

/// Split `H_msg` output into `(md, tree_idx, leaf_idx)`.
fn split_digest(p: &Params, digest: &[u8]) -> (Vec<u8>, u64, u32) {
    let md = digest[..p.md_bytes].to_vec();
    let tree_start = p.md_bytes;
    let mut tree_bytes = [0u8; 8];
    tree_bytes[8 - p.tree_bytes..].copy_from_slice(&digest[tree_start..tree_start + p.tree_bytes]);
    let mut tree = u64::from_be_bytes(tree_bytes);
    // The tree index spans `h − h_m` bits; 68−4 = 64 for 256f saturates u64.
    tree &= if p.h - p.h_m >= 64 {
        u64::MAX
    } else {
        (1u64 << (p.h - p.h_m)) - 1
    };
    let leaf_start = tree_start + p.tree_bytes;
    let mut leaf_bytes = [0u8; 4];
    leaf_bytes[4 - p.leaf_bytes..].copy_from_slice(&digest[leaf_start..leaf_start + p.leaf_bytes]);
    let mut leaf = u32::from_be_bytes(leaf_bytes);
    leaf &= (1u32 << p.h_m) - 1;
    (md, tree, leaf)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Compute `(PK.seed, PK.root)` from `SK.seed`/`PK.seed` (top-layer XMSS root).
fn derive_root(p: &Params, sk_seed: &[u8], pk_seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut root = [0u8; 32];
    let adrs = Adrs::new((p.d - 1) as u32, 0);
    xmss_node(p, sk_seed, 0, p.h_m, pk_seed, &adrs, &mut root[..p.n]);
    (pk_seed[..p.n].to_vec(), root[..p.n].to_vec())
}

/// Derive the public key for a secret key.
pub fn public_key(param: SlhDsaParam, sk: &SecretKey) -> Result<PublicKey> {
    let p = param.params();
    if sk.bytes.len() != param.sk_len() {
        return Err(Error::InvalidLength);
    }
    let (pk_seed, pk_root) = derive_root(&p, &sk.bytes[..p.n], &sk.bytes[2 * p.n..3 * p.n]);
    Ok(PublicKey {
        bytes: [pk_seed, pk_root].concat(),
    })
}

/// Generate a key pair from explicit seeds (`SK.seed`, `SK.prf`, `PK.seed`).
pub fn keygen_from_seeds(
    param: SlhDsaParam,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(PublicKey, SecretKey)> {
    let p = param.params();
    let n = p.n;
    if sk_seed.len() != n || sk_prf.len() != n || pk_seed.len() != n {
        return Err(Error::InvalidLength);
    }
    let (pk_seed_owned, pk_root) = derive_root(&p, sk_seed, pk_seed);
    let mut sk = SecretKey {
        bytes: Vec::with_capacity(param.sk_len()),
    };
    sk.bytes.extend_from_slice(sk_seed);
    sk.bytes.extend_from_slice(sk_prf);
    sk.bytes.extend_from_slice(pk_seed);
    sk.bytes.extend_from_slice(&pk_root);
    let pk = PublicKey {
        bytes: [pk_seed_owned, pk_root].concat(),
    };
    Ok((pk, sk))
}

/// Generate a key pair from an RNG.
pub fn keygen(
    param: SlhDsaParam,
    rng: &mut impl tpt_crypto_core::CryptoRng,
) -> Result<(PublicKey, SecretKey)> {
    let n = param.params().n;
    let mut sk_seed = [0u8; 32];
    let mut sk_prf = [0u8; 32];
    let mut pk_seed = [0u8; 32];
    rng.fill_bytes(&mut sk_seed[..n]);
    rng.fill_bytes(&mut sk_prf[..n]);
    rng.fill_bytes(&mut pk_seed[..n]);
    keygen_from_seeds(param, &sk_seed[..n], &sk_prf[..n], &pk_seed[..n])
}

/// Deterministic signing (`opt_rand = PK.seed`).
pub fn sign(param: SlhDsaParam, sk: &SecretKey, msg: &[u8], ctx: &[u8]) -> Result<Signature> {
    sign_internal(param, sk, msg, ctx, None)
}

/// Hedged signing with an explicit `opt_rand` (FIPS 205 §9.2 allows either).
pub fn sign_hedged(
    param: SlhDsaParam,
    sk: &SecretKey,
    msg: &[u8],
    ctx: &[u8],
    opt_rand: &[u8],
) -> Result<Signature> {
    let p = param.params();
    if opt_rand.len() != p.n {
        return Err(Error::InvalidLength);
    }
    sign_internal(param, sk, msg, ctx, Some(opt_rand))
}

fn sign_internal(
    param: SlhDsaParam,
    sk: &SecretKey,
    msg: &[u8],
    ctx: &[u8],
    opt_rand: Option<&[u8]>,
) -> Result<Signature> {
    let p = param.params();
    if sk.bytes.len() != param.sk_len() {
        return Err(Error::InvalidLength);
    }
    let m_prime = format_message(ctx, msg)?;

    let sk_seed = &sk.bytes[..p.n];
    let sk_prf = &sk.bytes[p.n..2 * p.n];
    let pk_seed = &sk.bytes[2 * p.n..3 * p.n];
    let opt = opt_rand.unwrap_or(pk_seed);

    // R = PRF_msg(SK.prf, opt_rand, M').
    let mut r = [0u8; 32];
    prf_msg(&p, sk_prf, opt, &m_prime, &mut r[..p.n]);

    // (md, tree, leaf) = split(H_msg(R, PK.seed, PK.root, M')).
    let dgst_len = p.md_bytes + p.tree_bytes + p.leaf_bytes;
    let mut digest = [0u8; 64];
    h_msg(
        &p,
        &r[..p.n],
        &sk.bytes[2 * p.n..4 * p.n],
        &m_prime,
        &mut digest[..dgst_len],
    );
    let (md, tree, leaf) = split_digest(&p, &digest[..dgst_len]);

    let mut adrs = Adrs::new(0, tree);
    adrs.with_type(TYPE_FORS_TREE);
    adrs.set_keypair(leaf);

    // FORS signature and root.
    let fors_len = p.k * (p.a + 1) * p.n;
    let mut sig = Vec::with_capacity(param.sig_len());
    sig.extend_from_slice(&r[..p.n]);
    sig.resize(p.n + fors_len, 0);
    fors_sign(
        &p,
        &md,
        sk_seed,
        pk_seed,
        &adrs,
        &mut sig[p.n..p.n + fors_len],
    );
    let mut fors_pk = [0u8; 32];
    fors_pk_from_sig(
        &p,
        &sig[p.n..p.n + fors_len],
        &md,
        pk_seed,
        &adrs,
        &mut fors_pk[..p.n],
    );

    // Hypertree signature over the FORS root.
    sig.resize(param.sig_len(), 0);
    ht_sign(
        &p,
        &fors_pk[..p.n],
        sk_seed,
        pk_seed,
        tree,
        leaf,
        &mut sig[p.n + fors_len..],
    );
    Ok(Signature { bytes: sig })
}

/// Verify a signature over `msg` with `ctx`.
pub fn verify(
    param: SlhDsaParam,
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    ctx: &[u8],
) -> Result<()> {
    let p = param.params();
    if pk.bytes.len() != param.pk_len() {
        return Err(Error::InvalidLength);
    }
    if sig.bytes.len() != param.sig_len() {
        return Err(Error::InvalidLength);
    }
    let m_prime = format_message(ctx, msg)?;
    let pk_seed = &pk.bytes[..p.n];
    let pk_root = &pk.bytes[p.n..2 * p.n];
    let r = &sig.bytes[..p.n];

    let dgst_len = p.md_bytes + p.tree_bytes + p.leaf_bytes;
    let mut digest = [0u8; 64];
    h_msg(&p, r, &pk.bytes, &m_prime, &mut digest[..dgst_len]);
    let (md, tree, leaf) = split_digest(&p, &digest[..dgst_len]);

    let mut adrs = Adrs::new(0, tree);
    adrs.with_type(TYPE_FORS_TREE);
    adrs.set_keypair(leaf);

    let fors_len = p.k * (p.a + 1) * p.n;
    let mut fors_pk = [0u8; 32];
    fors_pk_from_sig(
        &p,
        &sig.bytes[p.n..p.n + fors_len],
        &md,
        pk_seed,
        &adrs,
        &mut fors_pk[..p.n],
    );

    if ht_verify(
        &p,
        &fors_pk[..p.n],
        &sig.bytes[p.n + fors_len..],
        pk_seed,
        tree,
        leaf,
        pk_root,
    ) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Scratch probe (removed with the KAT commit).
#[doc(hidden)]
pub fn scratch_f_input(pk_seed: &[u8], sk42: &[u8], tree: u64, leaf: u32, index: u32) -> Vec<u8> {
    let p = SlhDsaParam::Sha2_128f.params();
    let mut adrs = Adrs::new(0, tree);
    adrs.with_type(TYPE_FORS_TREE);
    adrs.set_keypair(leaf);
    let mut f_adrs = adrs;
    f_adrs.set_height(0);
    f_adrs.set_index(index);
    let comp = f_adrs.compressed();
    let zeros = [0u8; 64];
    let mut dump = Vec::new();
    dump.extend_from_slice(&pk_seed[..p.n]);
    dump.extend_from_slice(&zeros[..64 - p.n]);
    dump.extend_from_slice(&comp);
    dump.extend_from_slice(&sk42[..p.n]);
    dump
}
