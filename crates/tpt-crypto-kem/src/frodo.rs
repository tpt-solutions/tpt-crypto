//! FrodoKEM-640-SHAKE (plain-LWE KEM, NIST round-3 parameter set, SHAKE128 for `A`).
//!
//! Transcribed from the reference C in `FrodoKEM/src/{kem,noise,util,frodo_macrify_reference}.c`
//! of the Microsoft reference repository (MIT). The KEM is checked byte-for-byte
//! against the official `PQCkemKAT_19888_shake.rsp` records (see `tests/frodo_kat.rs`).
//!
//! Scope: only the 640 parameter set with the SHAKE128 matrix generator. The 976/1344
//! sets and the AES-128 matrix generator are not implemented.
//!
//! Secret-dependent work: the noise sampler is a fixed-length comparison sum, the
//! decapsulation selector and output select are branch-free (`ct_verify` / `ct_select`
//! semantics), and secrets are zeroed on drop. The matrix products are fixed-length
//! and have no secret-dependent indices.

use alloc::vec;
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, Result, Zeroize};

// ---- Parameters (FrodoKEM-640) ----------------------------------------------------

/// Matrix dimension `n`.
const N: usize = 640;
/// Number of columns of the secret-side matrices (`n̄`).
const NBAR: usize = 8;
/// Bits per public-key / ciphertext entry (`log2 q`).
const LOGQ: u32 = 15;
/// `q - 1`, the mask that reduces a value modulo `q = 2^15`.
const Q_MASK: u16 = (1 << LOGQ) - 1;
/// Message bits carried per matrix entry (`B`).
const EXTRACTED_BITS: u32 = 2;
/// Bytes of the seed for `A`.
const SEED_A_LEN: usize = 16;
/// Bytes of the shared-secret / hash outputs (`CRYPTO_BYTES`).
const SS_LEN: usize = 16;
/// Bytes of `seedSE` (`2 * CRYPTO_BYTES`).
const SEED_SE_LEN: usize = 2 * SS_LEN;
/// Bytes of the random salt appended to the ciphertext.
const SALT_LEN: usize = 2 * SS_LEN;
/// Bytes of the message `mu` (`B * NBAR^2 / 8`).
const MU_LEN: usize = (EXTRACTED_BITS as usize) * NBAR * NBAR / 8;
/// Bytes of `H(pk)`.
const PKH_LEN: usize = SS_LEN;

/// `c1` length: `log q * n * n̄ / 8`.
const C1_LEN: usize = (LOGQ as usize) * N * NBAR / 8;
/// `c2` length: `log q * n̄^2 / 8`.
const C2_LEN: usize = (LOGQ as usize) * NBAR * NBAR / 8;
/// Public-key length: `seedA || pk_b`.
pub const PUBLIC_KEY_LEN: usize = SEED_A_LEN + C1_LEN;
/// Secret-key length: `s || pk || S || H(pk)`.
pub const SECRET_KEY_LEN: usize = SS_LEN + PUBLIC_KEY_LEN + 2 * N * NBAR + PKH_LEN;
/// Ciphertext length: `c1 || c2 || salt`.
pub const CIPHERTEXT_LEN: usize = C1_LEN + C2_LEN + SALT_LEN;
/// Shared-secret length.
pub const SHARED_SECRET_LEN: usize = SS_LEN;
/// Length of the randomness consumed by [`keygen_derand`]: `s || seedSE || z`.
pub const KEYGEN_RANDOM_LEN: usize = SS_LEN + SEED_SE_LEN + SEED_A_LEN;

/// Noise CDF table (13 entries) for the 640 set.
const CDF: [u16; 13] = [
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
];

/// Domain-separation prefix for the `S, E` expansion in keygen.
const DOMAIN_KEYGEN: u8 = 0x5F;
/// Domain-separation prefix for the `S', E'` expansion in encaps and decaps.
const DOMAIN_ENCAPS: u8 = 0x96;

// ---- Public types ------------------------------------------------------------------

/// FrodoKEM-640-SHAKE public key: `seedA || pk_b`.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Encoded public key bytes ([`PUBLIC_KEY_LEN`]).
    pub bytes: Vec<u8>,
}

/// FrodoKEM-640-SHAKE secret key: `s || pk || S || H(pk)`. Zeroed on drop.
pub struct SecretKey {
    /// Encoded secret key bytes ([`SECRET_KEY_LEN`]).
    pub bytes: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ---- Hashing, sampling, packing ----------------------------------------------------

fn shake(out: &mut [u8], input: &[u8]) {
    tpt_crypto_hash::sha3::shake128(input, out);
}

/// Map `n` pseudo-random 16-bit values to noise in place (`frodo_sample_n`).
///
/// Each output is the count of CDF thresholds below the magnitude, negated when the
/// low bit is set. The count is a fixed sum, so there is no secret-dependent branch.
fn sample_n(s: &mut [u16]) {
    for x in s.iter_mut() {
        let prnd = *x >> 1;
        let sign = *x & 1;
        let mut sample: u16 = 0;
        for &c in &CDF[..CDF.len() - 1] {
            // 1 when c < prnd: the wrapped difference has its top bit set.
            sample = sample.wrapping_add(c.wrapping_sub(prnd) >> 15);
        }
        *x = ((0u16.wrapping_sub(sign)) ^ sample).wrapping_add(sign);
    }
}

/// Expand the seed into `out`, a flat vector of `n` u16 values read little-endian.
fn shake_to_u16(out: &mut [u16], input: &[u8]) {
    let mut bytes = vec![0u8; 2 * out.len()];
    shake(&mut bytes, input);
    for (i, v) in out.iter_mut().enumerate() {
        *v = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
}

/// Generate matrix `A` (`n x n`, row-major). Row `i` is `SHAKE128(i_le16 || seedA)`.
fn gen_a(seed_a: &[u8]) -> Vec<u16> {
    let mut a = vec![0u16; N * N];
    let mut input = [0u8; 2 + SEED_A_LEN];
    input[2..].copy_from_slice(seed_a);
    let mut row_bytes = vec![0u8; 2 * N];
    for i in 0..N {
        input[..2].copy_from_slice(&(i as u16).to_le_bytes());
        shake(&mut row_bytes, &input);
        for j in 0..N {
            a[i * N + j] = u16::from_le_bytes([row_bytes[2 * j], row_bytes[2 * j + 1]]);
        }
    }
    a
}

/// Pack the low `lsb` bits of each entry, most significant bit first (`frodo_pack`).
fn pack(input: &[u16], lsb: u32, out: &mut [u8]) {
    out.fill(0);
    let mut pos = 0usize;
    for &v in input {
        for b in (0..lsb).rev() {
            if (v >> b) & 1 == 1 {
                out[pos / 8] |= 0x80 >> (pos % 8);
            }
            pos += 1;
        }
    }
}

/// Unpack `out.len()` values of `lsb` bits each, most significant bit first (`frodo_unpack`).
fn unpack(input: &[u8], lsb: u32, out: &mut [u16]) {
    let mut pos = 0usize;
    for v in out.iter_mut() {
        let mut acc = 0u16;
        for _ in 0..lsb {
            let bit = (input[pos / 8] >> (7 - (pos % 8))) & 1;
            acc = (acc << 1) | u16::from(bit);
            pos += 1;
        }
        *v = acc;
    }
}

/// Encode the 16-byte message into `NBAR^2` values (`frodo_key_encode`).
fn key_encode(mu: &[u8; MU_LEN]) -> [u16; NBAR * NBAR] {
    let mut out = [0u16; NBAR * NBAR];
    for i in 0..(NBAR * NBAR / 8) {
        let mut temp = u64::from(mu[2 * i]) | (u64::from(mu[2 * i + 1]) << 8);
        for j in 0..8 {
            out[8 * i + j] = ((temp & 3) << (LOGQ - EXTRACTED_BITS)) as u16;
            temp >>= EXTRACTED_BITS;
        }
    }
    out
}

/// Decode `NBAR^2` values back into the 16-byte message (`frodo_key_decode`).
fn key_decode(w: &[u16; NBAR * NBAR]) -> [u8; MU_LEN] {
    let mut out = [0u8; MU_LEN];
    for i in 0..(NBAR * NBAR / 8) {
        let mut templong = 0u64;
        for j in 0..8 {
            let x = w[8 * i + j] & Q_MASK;
            let t = ((x + (1 << (LOGQ - EXTRACTED_BITS - 1))) >> (LOGQ - EXTRACTED_BITS)) & 3;
            templong |= u64::from(t) << (EXTRACTED_BITS as usize * j);
        }
        out[2 * i] = templong as u8;
        out[2 * i + 1] = (templong >> 8) as u8;
    }
    out
}

// ---- Matrix arithmetic --------------------------------------------------------------

/// `out = e + A*s` with `s` of shape `NBAR x N` and `out` of shape `N x NBAR`
/// (`frodo_mul_add_as_plus_e`). Not reduced modulo `q`; packing takes the low bits.
fn mul_add_as_plus_e(seed_a: &[u8], s: &[u16], e: &[u16]) -> Vec<u16> {
    let a = gen_a(seed_a);
    let mut out = e.to_vec();
    for i in 0..N {
        for k in 0..NBAR {
            let mut sum = 0u16;
            for j in 0..N {
                sum = sum.wrapping_add(a[i * N + j].wrapping_mul(s[k * N + j]));
            }
            out[i * NBAR + k] = out[i * NBAR + k].wrapping_add(sum);
        }
    }
    out
}

/// `out = e + s*A` with `s` of shape `NBAR x N` and `out` of shape `NBAR x N`
/// (`frodo_mul_add_sa_plus_e`).
fn mul_add_sa_plus_e(seed_a: &[u8], s: &[u16], e: &[u16]) -> Vec<u16> {
    let a = gen_a(seed_a);
    let mut out = e.to_vec();
    for i in 0..N {
        for k in 0..NBAR {
            let mut sum = 0u16;
            for j in 0..N {
                sum = sum.wrapping_add(a[j * N + i].wrapping_mul(s[k * N + j]));
            }
            out[k * N + i] = out[k * N + i].wrapping_add(sum);
        }
    }
    out
}

/// `out = b*s^T mod q` with `b` of shape `NBAR x N` and `s` of shape `NBAR x N`
/// (`frodo_mul_bs`).
fn mul_bs(b: &[u16], s: &[u16]) -> [u16; NBAR * NBAR] {
    let mut out = [0u16; NBAR * NBAR];
    for i in 0..NBAR {
        for j in 0..NBAR {
            let mut acc = 0u16;
            for k in 0..N {
                acc = acc.wrapping_add(b[i * N + k].wrapping_mul(s[j * N + k]));
            }
            out[i * NBAR + j] = acc & Q_MASK;
        }
    }
    out
}

/// `out = e + s*b mod q` with `s` of shape `NBAR x N`, `b` of shape `N x NBAR`,
/// and `e` of shape `NBAR x NBAR` (`frodo_mul_add_sb_plus_e`).
fn mul_add_sb_plus_e(b: &[u16], s: &[u16], e: &[u16; NBAR * NBAR]) -> [u16; NBAR * NBAR] {
    let mut out = [0u16; NBAR * NBAR];
    for k in 0..NBAR {
        for i in 0..NBAR {
            let mut acc = e[k * NBAR + i];
            for j in 0..N {
                acc = acc.wrapping_add(s[k * N + j].wrapping_mul(b[j * NBAR + i]));
            }
            out[k * NBAR + i] = acc & Q_MASK;
        }
    }
    out
}

// ---- Constant-time comparison and selection ----------------------------------------

/// `0xff` if the two slices differ, `0x00` if equal, without branching on the data.
fn differs_mask(a: &[u16], b: &[u16]) -> u8 {
    let mut r = 0u32;
    for (x, y) in a.iter().zip(b) {
        r |= u32::from(x ^ y);
    }
    // `nonzero` is 1 iff r != 0: the top bit of `r | -r` is set exactly then.
    let nonzero = ((r | r.wrapping_neg()) >> 31) as u8;
    0u8.wrapping_sub(nonzero)
}

// ---- KEM ---------------------------------------------------------------------------

/// Expand `S` (`NBAR x N`, raw) and `E` (`N x NBAR`, raw) from `seed_se` with the given
/// domain prefix. Returns the sampled `(S, E)`.
fn sample_s_e_from_seed(domain: u8, seed_se: &[u8]) -> (Vec<u16>, Vec<u16>) {
    let mut input = [0u8; 1 + SEED_SE_LEN];
    input[0] = domain;
    input[1..].copy_from_slice(seed_se);
    let mut raw = vec![0u16; 2 * N * NBAR];
    shake_to_u16(&mut raw, &input);
    let e = raw.split_off(N * NBAR);
    let mut s = raw;
    sample_n(&mut s);
    let mut e = e;
    sample_n(&mut e);
    (s, e)
}

/// Like [`sample_s_e_from_seed`], plus the extra `NBAR^2` values `E''` used by encaps
/// and decaps. Returns `(S', E', E'')`.
fn sample_sp_ep_epp(seed_se: &[u8]) -> (Vec<u16>, Vec<u16>, [u16; NBAR * NBAR]) {
    let mut input = [0u8; 1 + SEED_SE_LEN];
    input[0] = DOMAIN_ENCAPS;
    input[1..].copy_from_slice(seed_se);
    let mut raw = vec![0u16; (2 * N + NBAR) * NBAR];
    shake_to_u16(&mut raw, &input);
    let mut epp_raw = [0u16; NBAR * NBAR];
    epp_raw.copy_from_slice(&raw[2 * N * NBAR..]);
    raw.truncate(2 * N * NBAR);
    let e = raw.split_off(N * NBAR);
    let mut sp = raw;
    sample_n(&mut sp);
    let mut ep = e;
    sample_n(&mut ep);
    sample_n(&mut epp_raw);
    (sp, ep, epp_raw)
}

/// Derandomized FrodoKEM-640-SHAKE key generation. `randomness` is `s || seedSE || z`.
pub fn keygen_derand(randomness: &[u8; KEYGEN_RANDOM_LEN]) -> (PublicKey, SecretKey) {
    let s_rand = &randomness[..SS_LEN];
    let seed_se = &randomness[SS_LEN..SS_LEN + SEED_SE_LEN];
    let z = &randomness[SS_LEN + SEED_SE_LEN..];

    let mut seed_a = [0u8; SEED_A_LEN];
    shake(&mut seed_a, z);

    let (mut s_mat, mut e_mat) = sample_s_e_from_seed(DOMAIN_KEYGEN, seed_se);
    let b = mul_add_as_plus_e(&seed_a, &s_mat, &e_mat);

    let mut pk = vec![0u8; PUBLIC_KEY_LEN];
    pk[..SEED_A_LEN].copy_from_slice(&seed_a);
    pack(&b, LOGQ, &mut pk[SEED_A_LEN..]);

    let mut pkh = [0u8; PKH_LEN];
    shake(&mut pkh, &pk);

    let mut sk = vec![0u8; SECRET_KEY_LEN];
    sk[..SS_LEN].copy_from_slice(s_rand);
    sk[SS_LEN..SS_LEN + PUBLIC_KEY_LEN].copy_from_slice(&pk);
    let s_off = SS_LEN + PUBLIC_KEY_LEN;
    for (i, v) in s_mat.iter().enumerate() {
        sk[s_off + 2 * i..s_off + 2 * i + 2].copy_from_slice(&v.to_le_bytes());
    }
    sk[SECRET_KEY_LEN - PKH_LEN..].copy_from_slice(&pkh);
    s_mat.zeroize();
    e_mat.zeroize();

    (PublicKey { bytes: pk }, SecretKey { bytes: sk })
}

/// FrodoKEM-640-SHAKE key generation from the RNG.
///
/// # Errors
///
/// Returns the RNG's error if it fails.
pub fn keygen(rng: &mut impl CryptoRng) -> Result<(PublicKey, SecretKey)> {
    let mut randomness = [0u8; KEYGEN_RANDOM_LEN];
    rng.try_fill_bytes(&mut randomness)?;
    let out = keygen_derand(&randomness);
    randomness.zeroize();
    Ok(out)
}

/// Derandomized encapsulation with message `mu` and salt. Returns `(ciphertext, ss)`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `pk` has the wrong length.
pub fn encapsulate_derand(
    pk: &[u8],
    mu: &[u8; MU_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(Error::InvalidLength);
    }
    let seed_a = &pk[..SEED_A_LEN];
    let pk_b = &pk[SEED_A_LEN..];

    let mut pkh = [0u8; PKH_LEN];
    shake(&mut pkh, pk);
    let mut g2in = [0u8; PKH_LEN + MU_LEN + SALT_LEN];
    g2in[..PKH_LEN].copy_from_slice(&pkh);
    g2in[PKH_LEN..PKH_LEN + MU_LEN].copy_from_slice(mu);
    g2in[PKH_LEN + MU_LEN..].copy_from_slice(salt);
    let mut g2out = [0u8; SEED_SE_LEN + SHARED_SECRET_LEN];
    shake(&mut g2out, &g2in);
    let (seed_se, k) = g2out.split_at(SEED_SE_LEN);

    let (mut sp, mut ep, mut epp) = sample_sp_ep_epp(seed_se);
    let bp = mul_add_sa_plus_e(seed_a, &sp, &ep);
    let mut c1 = vec![0u8; C1_LEN];
    pack(&bp, LOGQ, &mut c1);

    let b = {
        let mut b = vec![0u16; N * NBAR];
        unpack(pk_b, LOGQ, &mut b);
        b
    };
    let v = mul_add_sb_plus_e(&b, &sp, &epp);
    let enc = key_encode(mu);
    let mut c = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        c[i] = v[i].wrapping_add(enc[i]) & Q_MASK;
    }
    let mut c2 = vec![0u8; C2_LEN];
    pack(&c, LOGQ, &mut c2);

    let mut ct = vec![0u8; CIPHERTEXT_LEN];
    ct[..C1_LEN].copy_from_slice(&c1);
    ct[C1_LEN..C1_LEN + C2_LEN].copy_from_slice(&c2);
    ct[C1_LEN + C2_LEN..].copy_from_slice(salt);

    let mut fin = vec![0u8; CIPHERTEXT_LEN + SHARED_SECRET_LEN];
    fin[..CIPHERTEXT_LEN].copy_from_slice(&ct);
    fin[CIPHERTEXT_LEN..].copy_from_slice(k);
    let mut ss = [0u8; SHARED_SECRET_LEN];
    shake(&mut ss, &fin);
    fin.zeroize();
    sp.zeroize();
    ep.zeroize();
    epp.zeroize();
    Ok((ct, ss))
}

/// FrodoKEM-640-SHAKE encapsulation to `pk` drawing `mu` and the salt from the RNG.
///
/// # Errors
///
/// [`Error::InvalidLength`] for a malformed `pk`, or the RNG's error.
pub fn encapsulate(
    pk: &PublicKey,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    let mut mu = [0u8; MU_LEN];
    let mut salt = [0u8; SALT_LEN];
    rng.try_fill_bytes(&mut mu)?;
    rng.try_fill_bytes(&mut salt)?;
    let out = encapsulate_derand(&pk.bytes, &mu, &salt);
    mu.zeroize();
    out
}

/// FrodoKEM-640-SHAKE decapsulation with implicit rejection.
///
/// A ciphertext that does not re-encrypt to itself yields `F(ct || s)` rather than an
/// error, so the caller cannot tell rejection from success.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `sk` or `ct` has the wrong length.
pub fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if sk.bytes.len() != SECRET_KEY_LEN || ct.len() != CIPHERTEXT_LEN {
        return Err(Error::InvalidLength);
    }
    let s_rand = &sk.bytes[..SS_LEN];
    let pk = &sk.bytes[SS_LEN..SS_LEN + PUBLIC_KEY_LEN];
    let s_off = SS_LEN + PUBLIC_KEY_LEN;
    let pkh = &sk.bytes[SECRET_KEY_LEN - PKH_LEN..];
    let seed_a = &pk[..SEED_A_LEN];
    let pk_b = &pk[SEED_A_LEN..];

    let mut s_mat = vec![0u16; N * NBAR];
    for (i, v) in s_mat.iter_mut().enumerate() {
        *v = u16::from_le_bytes([sk.bytes[s_off + 2 * i], sk.bytes[s_off + 2 * i + 1]]);
    }

    let c1 = &ct[..C1_LEN];
    let c2 = &ct[C1_LEN..C1_LEN + C2_LEN];
    let salt = &ct[C1_LEN + C2_LEN..];

    let mut bp = vec![0u16; N * NBAR];
    unpack(c1, LOGQ, &mut bp);
    let mut c = [0u16; NBAR * NBAR];
    {
        let mut tmp = [0u16; NBAR * NBAR];
        unpack(c2, LOGQ, &mut tmp);
        c.copy_from_slice(&tmp);
    }

    // W = C - B'*S, then recover mu'.
    let bs = mul_bs(&bp, &s_mat);
    let mut w = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        w[i] = c[i].wrapping_sub(bs[i]) & Q_MASK;
    }
    let mut mu_p = key_decode(&w);

    // (seedSE', k') = G(pkh || mu' || salt).
    let mut g2in = [0u8; PKH_LEN + MU_LEN + SALT_LEN];
    g2in[..PKH_LEN].copy_from_slice(pkh);
    g2in[PKH_LEN..PKH_LEN + MU_LEN].copy_from_slice(&mu_p);
    g2in[PKH_LEN + MU_LEN..].copy_from_slice(salt);
    let mut g2out = [0u8; SEED_SE_LEN + SHARED_SECRET_LEN];
    shake(&mut g2out, &g2in);
    let (seed_se_p, k_p) = g2out.split_at(SEED_SE_LEN);

    let (mut sp, mut ep, mut epp) = sample_sp_ep_epp(seed_se_p);
    let mut bbp = mul_add_sa_plus_e(seed_a, &sp, &ep);
    let b = {
        let mut b = vec![0u16; N * NBAR];
        unpack(pk_b, LOGQ, &mut b);
        b
    };
    let wv = mul_add_sb_plus_e(&b, &sp, &epp);
    let enc = key_encode(&mu_p);
    let mut cc = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        cc[i] = wv[i].wrapping_add(enc[i]) & Q_MASK;
    }

    for v in bbp.iter_mut() {
        *v &= Q_MASK;
    }
    // Accept k' only if re-encryption matches (B' == BB' and C == CC); else use s.
    let reject = differs_mask(&bp, &bbp) | differs_mask(&c, &cc);
    let mut k_sel = [0u8; SHARED_SECRET_LEN];
    for i in 0..SHARED_SECRET_LEN {
        k_sel[i] = ((!reject) & k_p[i]) | (reject & s_rand[i]);
    }

    let mut fin = vec![0u8; CIPHERTEXT_LEN + SHARED_SECRET_LEN];
    fin[..CIPHERTEXT_LEN].copy_from_slice(ct);
    fin[CIPHERTEXT_LEN..].copy_from_slice(&k_sel);
    let mut ss = [0u8; SHARED_SECRET_LEN];
    shake(&mut ss, &fin);

    fin.zeroize();
    k_sel.zeroize();
    mu_p.zeroize();
    g2out.zeroize();
    s_mat.zeroize();
    sp.zeroize();
    ep.zeroize();
    epp.zeroize();
    w.zeroize();
    Ok(ss)
}
