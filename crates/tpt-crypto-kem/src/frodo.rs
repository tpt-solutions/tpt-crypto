//! FrodoKEM (plain-LWE KEM, NIST round-3 parameter sets 640, 976 and 1344).
//!
//! Transcribed from the reference C in `FrodoKEM/src/{kem,noise,util,frodo_macrify_reference}.c`
//! and `frodo{640,976,1344}.c` of the Microsoft reference repository (MIT). One generic
//! implementation covers every set through [`FrodoParams`]. Two matrix constructions
//! are exposed as modules:
//!
//! - [`shake`]: the public matrix `A` is expanded with SHAKE128 (`FrodoKEM-*-SHAKE`).
//! - [`aes`]: `A` is expanded with AES-128-ECB (`FrodoKEM-*-AES`).
//!
//! The KEM hash is SHAKE128 for 640 and SHAKE256 for 976 and 1344, as in the reference.
//! Each set and variant is checked byte for byte against official reference KAT
//! records (`tests/frodo_kat.rs`).
//!
//! Secret-dependent work: the noise sampler is a fixed-length comparison sum, the
//! decapsulation selector and output select are branch-free (`ct_verify` / `ct_select`
//! semantics), and secrets are zeroed on drop. The matrix products are fixed-length
//! and have no secret-dependent indices.

use alloc::vec;
use alloc::vec::Vec;
use tpt_crypto_aead::Aes;
use tpt_crypto_core::{CryptoRng, Error, Result, Zeroize};

/// Number of columns of the secret-side matrices (`n̄`). The same for every set.
const NBAR: usize = 8;
/// Bytes of the seed for `A`. The same for every set.
const SEED_A_LEN: usize = 16;

/// Per-set FrodoKEM parameters.
pub trait FrodoParams {
    /// Matrix dimension `n`.
    const N: usize;
    /// Bits per public-key / ciphertext entry (`log2 q`).
    const LOGQ: u32;
    /// Message bits carried per matrix entry (`B`).
    const EXTRACTED_BITS: u32;
    /// Bytes of the shared secret and of the hash outputs (`CRYPTO_BYTES`).
    const CRYPTO_BYTES: usize;
    /// Noise CDF table.
    const CDF: &'static [u16];
    /// Whether the KEM hash is SHAKE256 (976, 1344) rather than SHAKE128 (640).
    const SHAKE256: bool;

    /// Bytes of the message `mu` (`B * NBAR^2 / 8`).
    const MU_LEN: usize = Self::EXTRACTED_BITS as usize * NBAR * NBAR / 8;
    /// Bytes of the random salt (`2 * CRYPTO_BYTES`).
    const SALT_LEN: usize = 2 * Self::CRYPTO_BYTES;
    /// Bytes of `seedSE` (`2 * CRYPTO_BYTES`).
    const SEED_SE_LEN: usize = 2 * Self::CRYPTO_BYTES;
    /// Bytes of `H(pk)` (`CRYPTO_BYTES`).
    const PKH_LEN: usize = Self::CRYPTO_BYTES;
    /// `c1` length: `log q * n * n̄ / 8`.
    const C1_LEN: usize = Self::LOGQ as usize * Self::N * NBAR / 8;
    /// `c2` length: `log q * n̄^2 / 8`.
    const C2_LEN: usize = Self::LOGQ as usize * NBAR * NBAR / 8;
    /// Public-key length: `seedA || pk_b`.
    const PUBLIC_KEY_LEN: usize = SEED_A_LEN + Self::C1_LEN;
    /// Secret-key length: `s || pk || S || H(pk)`.
    const SECRET_KEY_LEN: usize =
        Self::CRYPTO_BYTES + Self::PUBLIC_KEY_LEN + 2 * Self::N * NBAR + Self::PKH_LEN;
    /// Ciphertext length: `c1 || c2 || salt`.
    const CIPHERTEXT_LEN: usize = Self::C1_LEN + Self::C2_LEN + Self::SALT_LEN;
    /// Randomness consumed by key generation: `s || seedSE || z`.
    const KEYGEN_RANDOM_LEN: usize = Self::CRYPTO_BYTES + Self::SEED_SE_LEN + SEED_A_LEN;
}

/// FrodoKEM-640 parameters (`n = 640`, `q = 2^15`, SHAKE128 hash).
pub struct Frodo640;

impl FrodoParams for Frodo640 {
    const N: usize = 640;
    const LOGQ: u32 = 15;
    const EXTRACTED_BITS: u32 = 2;
    const CRYPTO_BYTES: usize = 16;
    const CDF: &'static [u16] = &[
        4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
    ];
    const SHAKE256: bool = false;
}

/// FrodoKEM-976 parameters (`n = 976`, `q = 2^16`, SHAKE256 hash).
pub struct Frodo976;

impl FrodoParams for Frodo976 {
    const N: usize = 976;
    const LOGQ: u32 = 16;
    const EXTRACTED_BITS: u32 = 3;
    const CRYPTO_BYTES: usize = 24;
    const CDF: &'static [u16] = &[
        5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
    ];
    const SHAKE256: bool = true;
}

/// FrodoKEM-1344 parameters (`n = 1344`, `q = 2^16`, SHAKE256 hash).
pub struct Frodo1344;

impl FrodoParams for Frodo1344 {
    const N: usize = 1344;
    const LOGQ: u32 = 16;
    const EXTRACTED_BITS: u32 = 4;
    const CRYPTO_BYTES: usize = 32;
    const CDF: &'static [u16] = &[9142, 23462, 30338, 32361, 32725, 32765, 32767];
    const SHAKE256: bool = true;
}

/// Domain-separation prefix for the `S, E` expansion in keygen.
const DOMAIN_KEYGEN: u8 = 0x5F;
/// Domain-separation prefix for the `S', E'` expansion in encaps and decaps.
const DOMAIN_ENCAPS: u8 = 0x96;

/// Which construction expands the public matrix `A` from `seedA`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MatrixGen {
    /// Row `i` of `A` is `SHAKE128(i_le16 || seedA)`.
    Shake128,
    /// `A` is AES-128-ECB under `seedA`, applied to blocks `(i_le16, j_le16, 0...)`.
    Aes128,
}

// ---- Public types ------------------------------------------------------------------

/// FrodoKEM public key: `seedA || pk_b`.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Encoded public key bytes.
    pub bytes: Vec<u8>,
}

/// FrodoKEM secret key: `s || pk || S || H(pk)`. Zeroed on drop.
pub struct SecretKey {
    /// Encoded secret key bytes.
    pub bytes: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ---- Hashing, sampling, packing ----------------------------------------------------

/// The KEM hash for set `P`: SHAKE128 for 640, SHAKE256 for 976 and 1344.
fn hash<P: FrodoParams>(out: &mut [u8], input: &[u8]) {
    if P::SHAKE256 {
        tpt_crypto_hash::sha3::shake256(input, out);
    } else {
        tpt_crypto_hash::sha3::shake128(input, out);
    }
}

/// `q - 1` for set `P`, as a 16-bit mask.
fn q_mask<P: FrodoParams>() -> u16 {
    ((1u32 << P::LOGQ) - 1) as u16
}

/// Map pseudo-random 16-bit values to noise in place (`frodo_sample_n`).
///
/// Each output is the count of CDF thresholds below the magnitude, negated when the
/// low bit is set. The count is a fixed sum, so there is no secret-dependent branch.
fn sample_n<P: FrodoParams>(s: &mut [u16]) {
    let cdf = P::CDF;
    for x in s.iter_mut() {
        let prnd = *x >> 1;
        let sign = *x & 1;
        let mut sample: u16 = 0;
        for &c in &cdf[..cdf.len() - 1] {
            // 1 when c < prnd: the wrapped difference has its top bit set.
            sample = sample.wrapping_add(c.wrapping_sub(prnd) >> 15);
        }
        *x = ((0u16.wrapping_sub(sign)) ^ sample).wrapping_add(sign);
    }
}

/// Expand the KEM hash of `input` into `out`, a flat vector of u16 values read
/// little-endian.
fn hash_to_u16<P: FrodoParams>(out: &mut [u16], input: &[u8]) {
    let mut bytes = vec![0u8; 2 * out.len()];
    hash::<P>(&mut bytes, input);
    for (i, v) in out.iter_mut().enumerate() {
        *v = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
}

/// Generate the `n x n` matrix `A` (row-major) with the chosen construction.
fn gen_a<P: FrodoParams>(m: MatrixGen, seed_a: &[u8]) -> Vec<u16> {
    let n = P::N;
    let mut a = vec![0u16; n * n];
    match m {
        MatrixGen::Shake128 => {
            // The matrix rows are always SHAKE128, for every set (reference macrify).
            let mut input = [0u8; 2 + SEED_A_LEN];
            input[2..].copy_from_slice(seed_a);
            let mut row_bytes = vec![0u8; 2 * n];
            for i in 0..n {
                input[..2].copy_from_slice(&(i as u16).to_le_bytes());
                tpt_crypto_hash::sha3::shake128(&input, &mut row_bytes);
                for j in 0..n {
                    a[i * n + j] = u16::from_le_bytes([row_bytes[2 * j], row_bytes[2 * j + 1]]);
                }
            }
        }
        MatrixGen::Aes128 => {
            // Each 16-byte block is (i_le16, j_le16, 0...), encrypted in ECB mode under
            // seedA. The 8 output words fill A[i][j..j+8].
            let aes = Aes::new_128(seed_a);
            for i in 0..n {
                for j in (0..n).step_by(8) {
                    let mut block = [0u8; 16];
                    block[..2].copy_from_slice(&(i as u16).to_le_bytes());
                    block[2..4].copy_from_slice(&(j as u16).to_le_bytes());
                    let enc = aes.encrypt_block(&block);
                    for t in 0..8 {
                        a[i * n + j + t] = u16::from_le_bytes([enc[2 * t], enc[2 * t + 1]]);
                    }
                }
            }
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
            // Branch-free: the value may derive from secrets (encaps and keygen pack them).
            out[pos / 8] |= (((v >> b) & 1) as u8) << (7 - (pos % 8));
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

/// Encode the `MU_LEN`-byte message into `NBAR^2` values (`frodo_key_encode`).
fn key_encode<P: FrodoParams>(mu: &[u8]) -> [u16; NBAR * NBAR] {
    let b = P::EXTRACTED_BITS;
    let mut out = [0u16; NBAR * NBAR];
    for i in 0..(NBAR * NBAR / 8) {
        let mut temp = 0u64;
        for j in 0..b as usize {
            temp |= u64::from(mu[b as usize * i + j]) << (8 * j);
        }
        for j in 0..8 {
            out[8 * i + j] = ((temp & ((1u64 << b) - 1)) << (P::LOGQ - b)) as u16;
            temp >>= b;
        }
    }
    out
}

/// Decode `NBAR^2` values back into the `MU_LEN`-byte message (`frodo_key_decode`).
fn key_decode<P: FrodoParams>(w: &[u16; NBAR * NBAR]) -> Vec<u8> {
    let b = P::EXTRACTED_BITS;
    let qmask = (1u32 << P::LOGQ) - 1;
    let mut out = vec![0u8; P::MU_LEN];
    for i in 0..(NBAR * NBAR / 8) {
        let mut templong = 0u64;
        for j in 0..8 {
            let x = u32::from(w[8 * i + j]) & qmask;
            let t = ((x + (1 << (P::LOGQ - b - 1))) >> (P::LOGQ - b)) & ((1 << b) - 1);
            templong |= u64::from(t) << (b as usize * j);
        }
        for j in 0..b as usize {
            out[b as usize * i + j] = (templong >> (8 * j)) as u8;
        }
    }
    out
}

// ---- Matrix arithmetic --------------------------------------------------------------

/// `out = e + A*s` with `s` of shape `NBAR x N` and `out` of shape `N x NBAR`
/// (`frodo_mul_add_as_plus_e`). Not reduced modulo `q`; packing takes the low bits.
fn mul_add_as_plus_e<P: FrodoParams>(
    m: MatrixGen,
    seed_a: &[u8],
    s: &[u16],
    e: &[u16],
) -> Vec<u16> {
    let n = P::N;
    let a = gen_a::<P>(m, seed_a);
    let mut out = e.to_vec();
    for i in 0..n {
        for k in 0..NBAR {
            let mut sum = 0u16;
            for j in 0..n {
                sum = sum.wrapping_add(a[i * n + j].wrapping_mul(s[k * n + j]));
            }
            out[i * NBAR + k] = out[i * NBAR + k].wrapping_add(sum);
        }
    }
    out
}

/// `out = e + s*A` with `s` of shape `NBAR x N` and `out` of shape `NBAR x N`
/// (`frodo_mul_add_sa_plus_e`).
fn mul_add_sa_plus_e<P: FrodoParams>(
    m: MatrixGen,
    seed_a: &[u8],
    s: &[u16],
    e: &[u16],
) -> Vec<u16> {
    let n = P::N;
    let a = gen_a::<P>(m, seed_a);
    let mut out = e.to_vec();
    for i in 0..n {
        for k in 0..NBAR {
            let mut sum = 0u16;
            for j in 0..n {
                sum = sum.wrapping_add(a[j * n + i].wrapping_mul(s[k * n + j]));
            }
            out[k * n + i] = out[k * n + i].wrapping_add(sum);
        }
    }
    out
}

/// `out = b*s^T mod q` with `b` of shape `NBAR x N` and `s` of shape `NBAR x N`
/// (`frodo_mul_bs`).
fn mul_bs<P: FrodoParams>(b: &[u16], s: &[u16]) -> [u16; NBAR * NBAR] {
    let n = P::N;
    let qm = q_mask::<P>();
    let mut out = [0u16; NBAR * NBAR];
    for i in 0..NBAR {
        for j in 0..NBAR {
            let mut acc = 0u16;
            for k in 0..n {
                acc = acc.wrapping_add(b[i * n + k].wrapping_mul(s[j * n + k]));
            }
            out[i * NBAR + j] = acc & qm;
        }
    }
    out
}

/// `out = e + s*b mod q` with `s` of shape `NBAR x N`, `b` of shape `N x NBAR`,
/// and `e` of shape `NBAR x NBAR` (`frodo_mul_add_sb_plus_e`).
fn mul_add_sb_plus_e<P: FrodoParams>(
    b: &[u16],
    s: &[u16],
    e: &[u16; NBAR * NBAR],
) -> [u16; NBAR * NBAR] {
    let n = P::N;
    let qm = q_mask::<P>();
    let mut out = [0u16; NBAR * NBAR];
    for k in 0..NBAR {
        for i in 0..NBAR {
            let mut acc = e[k * NBAR + i];
            for j in 0..n {
                acc = acc.wrapping_add(s[k * n + j].wrapping_mul(b[j * NBAR + i]));
            }
            out[k * NBAR + i] = acc & qm;
        }
    }
    out
}

// ---- Constant-time comparison -------------------------------------------------------

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

// ---- KEM core ----------------------------------------------------------------------

/// Expand `S` (`NBAR x N`) and `E` (`N x NBAR`) from `seed_se` with the keygen domain.
fn sample_s_e_from_seed<P: FrodoParams>(seed_se: &[u8]) -> (Vec<u16>, Vec<u16>) {
    let n = P::N;
    let mut input = vec![0u8; 1 + P::SEED_SE_LEN];
    input[0] = DOMAIN_KEYGEN;
    input[1..].copy_from_slice(seed_se);
    let mut raw = vec![0u16; 2 * n * NBAR];
    hash_to_u16::<P>(&mut raw, &input);
    let mut e = raw.split_off(n * NBAR);
    let mut s = raw;
    sample_n::<P>(&mut s);
    sample_n::<P>(&mut e);
    (s, e)
}

/// Expand `S'` (`NBAR x N`), `E'` (`N x NBAR`) and `E''` (`NBAR x NBAR`) from `seed_se`
/// with the encaps domain.
fn sample_sp_ep_epp<P: FrodoParams>(seed_se: &[u8]) -> (Vec<u16>, Vec<u16>, [u16; NBAR * NBAR]) {
    let n = P::N;
    let mut input = vec![0u8; 1 + P::SEED_SE_LEN];
    input[0] = DOMAIN_ENCAPS;
    input[1..].copy_from_slice(seed_se);
    let mut raw = vec![0u16; (2 * n + NBAR) * NBAR];
    hash_to_u16::<P>(&mut raw, &input);
    let mut epp_raw = vec![0u16; NBAR * NBAR];
    epp_raw.copy_from_slice(&raw[2 * n * NBAR..]);
    raw.truncate(2 * n * NBAR);
    let mut ep = raw.split_off(n * NBAR);
    let mut sp = raw;
    sample_n::<P>(&mut sp);
    sample_n::<P>(&mut ep);
    sample_n::<P>(&mut epp_raw);
    let mut epp = [0u16; NBAR * NBAR];
    epp.copy_from_slice(&epp_raw);
    epp_raw.zeroize();
    (sp, ep, epp)
}

fn keygen_with<P: FrodoParams>(m: MatrixGen, randomness: &[u8]) -> (PublicKey, SecretKey) {
    let cb = P::CRYPTO_BYTES;
    let s_rand = &randomness[..cb];
    let seed_se = &randomness[cb..cb + P::SEED_SE_LEN];
    let z = &randomness[cb + P::SEED_SE_LEN..];

    let mut seed_a = [0u8; SEED_A_LEN];
    hash::<P>(&mut seed_a, z);

    let (mut s_mat, mut e_mat) = sample_s_e_from_seed::<P>(seed_se);
    let b = mul_add_as_plus_e::<P>(m, &seed_a, &s_mat, &e_mat);

    let mut pk = vec![0u8; P::PUBLIC_KEY_LEN];
    pk[..SEED_A_LEN].copy_from_slice(&seed_a);
    pack(&b, P::LOGQ, &mut pk[SEED_A_LEN..]);

    let mut pkh = vec![0u8; P::PKH_LEN];
    hash::<P>(&mut pkh, &pk);

    let mut sk = vec![0u8; P::SECRET_KEY_LEN];
    sk[..cb].copy_from_slice(s_rand);
    sk[cb..cb + P::PUBLIC_KEY_LEN].copy_from_slice(&pk);
    let s_off = cb + P::PUBLIC_KEY_LEN;
    for (i, v) in s_mat.iter().enumerate() {
        sk[s_off + 2 * i..s_off + 2 * i + 2].copy_from_slice(&v.to_le_bytes());
    }
    let pkh_off = P::SECRET_KEY_LEN - P::PKH_LEN;
    sk[pkh_off..].copy_from_slice(&pkh);
    s_mat.zeroize();
    e_mat.zeroize();

    (PublicKey { bytes: pk }, SecretKey { bytes: sk })
}

fn encapsulate_with<P: FrodoParams>(
    m: MatrixGen,
    pk: &[u8],
    mu: &[u8],
    salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cb = P::CRYPTO_BYTES;
    if pk.len() != P::PUBLIC_KEY_LEN || mu.len() != P::MU_LEN || salt.len() != P::SALT_LEN {
        return Err(Error::InvalidLength);
    }
    let seed_a = &pk[..SEED_A_LEN];
    let pk_b = &pk[SEED_A_LEN..];

    let mut pkh = vec![0u8; P::PKH_LEN];
    hash::<P>(&mut pkh, pk);
    let mut g2in = Vec::with_capacity(P::PKH_LEN + P::MU_LEN + P::SALT_LEN);
    g2in.extend_from_slice(&pkh);
    g2in.extend_from_slice(mu);
    g2in.extend_from_slice(salt);
    let mut g2out = vec![0u8; P::SEED_SE_LEN + cb];
    hash::<P>(&mut g2out, &g2in);
    let (seed_se, k) = g2out.split_at(P::SEED_SE_LEN);

    let (mut sp, mut ep, mut epp) = sample_sp_ep_epp::<P>(seed_se);
    let bp = mul_add_sa_plus_e::<P>(m, seed_a, &sp, &ep);
    let mut c1 = vec![0u8; P::C1_LEN];
    pack(&bp, P::LOGQ, &mut c1);

    let mut b = vec![0u16; P::N * NBAR];
    unpack(pk_b, P::LOGQ, &mut b);
    let v = mul_add_sb_plus_e::<P>(&b, &sp, &epp);
    let enc = key_encode::<P>(mu);
    let qm = q_mask::<P>();
    let mut c = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        c[i] = v[i].wrapping_add(enc[i]) & qm;
    }
    let mut c2 = vec![0u8; P::C2_LEN];
    pack(&c, P::LOGQ, &mut c2);

    let mut ct = vec![0u8; P::CIPHERTEXT_LEN];
    ct[..P::C1_LEN].copy_from_slice(&c1);
    ct[P::C1_LEN..P::C1_LEN + P::C2_LEN].copy_from_slice(&c2);
    ct[P::C1_LEN + P::C2_LEN..].copy_from_slice(salt);

    let mut fin = vec![0u8; P::CIPHERTEXT_LEN + cb];
    fin[..P::CIPHERTEXT_LEN].copy_from_slice(&ct);
    fin[P::CIPHERTEXT_LEN..].copy_from_slice(k);
    let mut ss = vec![0u8; cb];
    hash::<P>(&mut ss, &fin);

    fin.zeroize();
    g2out.zeroize();
    sp.zeroize();
    ep.zeroize();
    epp.zeroize();
    b.zeroize();
    Ok((ct, ss))
}

fn decapsulate_with<P: FrodoParams>(m: MatrixGen, sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
    let cb = P::CRYPTO_BYTES;
    if sk.bytes.len() != P::SECRET_KEY_LEN || ct.len() != P::CIPHERTEXT_LEN {
        return Err(Error::InvalidLength);
    }
    let s_rand = &sk.bytes[..cb];
    let pk = &sk.bytes[cb..cb + P::PUBLIC_KEY_LEN];
    let s_off = cb + P::PUBLIC_KEY_LEN;
    let pkh = &sk.bytes[P::SECRET_KEY_LEN - P::PKH_LEN..];
    let seed_a = &pk[..SEED_A_LEN];
    let pk_b = &pk[SEED_A_LEN..];

    let mut s_mat = vec![0u16; P::N * NBAR];
    for (i, v) in s_mat.iter_mut().enumerate() {
        *v = u16::from_le_bytes([sk.bytes[s_off + 2 * i], sk.bytes[s_off + 2 * i + 1]]);
    }

    let c1 = &ct[..P::C1_LEN];
    let c2 = &ct[P::C1_LEN..P::C1_LEN + P::C2_LEN];
    let salt = &ct[P::C1_LEN + P::C2_LEN..];

    let qm = q_mask::<P>();
    let mut bp = vec![0u16; P::N * NBAR];
    unpack(c1, P::LOGQ, &mut bp);
    let mut c = [0u16; NBAR * NBAR];
    unpack(c2, P::LOGQ, &mut c);

    // W = C - B'*S, then recover mu'.
    let bs = mul_bs::<P>(&bp, &s_mat);
    let mut w = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        w[i] = c[i].wrapping_sub(bs[i]) & qm;
    }
    let mut mu_p = key_decode::<P>(&w);

    // (seedSE', k') = G(pkh || mu' || salt).
    let mut g2in = Vec::with_capacity(P::PKH_LEN + P::MU_LEN + P::SALT_LEN);
    g2in.extend_from_slice(pkh);
    g2in.extend_from_slice(&mu_p);
    g2in.extend_from_slice(salt);
    let mut g2out = vec![0u8; P::SEED_SE_LEN + cb];
    hash::<P>(&mut g2out, &g2in);
    let (seed_se_p, k_p) = g2out.split_at(P::SEED_SE_LEN);

    let (mut sp, mut ep, mut epp) = sample_sp_ep_epp::<P>(seed_se_p);
    let mut bbp = mul_add_sa_plus_e::<P>(m, seed_a, &sp, &ep);
    let mut b = vec![0u16; P::N * NBAR];
    unpack(pk_b, P::LOGQ, &mut b);
    let wv = mul_add_sb_plus_e::<P>(&b, &sp, &epp);
    let enc = key_encode::<P>(&mu_p);
    let mut cc = [0u16; NBAR * NBAR];
    for i in 0..NBAR * NBAR {
        cc[i] = wv[i].wrapping_add(enc[i]) & qm;
    }

    for v in bbp.iter_mut() {
        *v &= qm;
    }
    // Accept k' only if re-encryption matches (B' == BB' and C == CC); else use s.
    let reject = differs_mask(&bp, &bbp) | differs_mask(&c, &cc);
    let mut k_sel = vec![0u8; cb];
    for i in 0..cb {
        k_sel[i] = ((!reject) & k_p[i]) | (reject & s_rand[i]);
    }

    let mut fin = vec![0u8; P::CIPHERTEXT_LEN + cb];
    fin[..P::CIPHERTEXT_LEN].copy_from_slice(ct);
    fin[P::CIPHERTEXT_LEN..].copy_from_slice(&k_sel);
    let mut ss = vec![0u8; cb];
    hash::<P>(&mut ss, &fin);

    fin.zeroize();
    k_sel.zeroize();
    mu_p.zeroize();
    g2out.zeroize();
    s_mat.zeroize();
    sp.zeroize();
    ep.zeroize();
    epp.zeroize();
    b.zeroize();
    w.zeroize();
    Ok(ss)
}

fn keygen_from_rng<P: FrodoParams>(
    m: MatrixGen,
    rng: &mut impl CryptoRng,
) -> Result<(PublicKey, SecretKey)> {
    let mut randomness = vec![0u8; P::KEYGEN_RANDOM_LEN];
    rng.try_fill_bytes(&mut randomness)?;
    let out = keygen_with::<P>(m, &randomness);
    randomness.zeroize();
    Ok(out)
}

fn encapsulate_from_rng<P: FrodoParams>(
    m: MatrixGen,
    pk: &PublicKey,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut mu = vec![0u8; P::MU_LEN];
    let mut salt = vec![0u8; P::SALT_LEN];
    rng.try_fill_bytes(&mut mu)?;
    rng.try_fill_bytes(&mut salt)?;
    let out = encapsulate_with::<P>(m, &pk.bytes, &mu, &salt);
    mu.zeroize();
    out
}

/// Matrix `A` expanded with SHAKE128: `FrodoKEM-*-SHAKE`.
pub mod shake {
    use super::*;

    /// Derandomized key generation for set `P`. `randomness` is `s || seedSE || z` and
    /// must be [`FrodoParams::KEYGEN_RANDOM_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `randomness` has the wrong length.
    pub fn keygen_derand<P: FrodoParams>(randomness: &[u8]) -> Result<(PublicKey, SecretKey)> {
        if randomness.len() != P::KEYGEN_RANDOM_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(keygen_with::<P>(MatrixGen::Shake128, randomness))
    }

    /// Key generation for set `P` from the RNG.
    ///
    /// # Errors
    ///
    /// Returns the RNG's error if it fails.
    pub fn keygen<P: FrodoParams>(rng: &mut impl CryptoRng) -> Result<(PublicKey, SecretKey)> {
        keygen_from_rng::<P>(MatrixGen::Shake128, rng)
    }

    /// Derandomized encapsulation for set `P` with message `mu` and salt. Returns
    /// `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `pk`, `mu` or `salt` has the wrong length.
    pub fn encapsulate_derand<P: FrodoParams>(
        pk: &[u8],
        mu: &[u8],
        salt: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        encapsulate_with::<P>(MatrixGen::Shake128, pk, mu, salt)
    }

    /// Encapsulation to `pk`, drawing `mu` and the salt from the RNG.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a malformed `pk`, or the RNG's error.
    pub fn encapsulate<P: FrodoParams>(
        pk: &PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        encapsulate_from_rng::<P>(MatrixGen::Shake128, pk, rng)
    }

    /// Decapsulation with implicit rejection: a ciphertext that does not re-encrypt to
    /// itself yields `F(ct || s)` rather than an error.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `sk` or `ct` has the wrong length.
    pub fn decapsulate<P: FrodoParams>(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
        decapsulate_with::<P>(MatrixGen::Shake128, sk, ct)
    }
}

/// Matrix `A` expanded with AES-128-ECB: `FrodoKEM-*-AES`.
pub mod aes {
    use super::*;

    /// Derandomized key generation for set `P`. See [`super::shake::keygen_derand`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `randomness` has the wrong length.
    pub fn keygen_derand<P: FrodoParams>(randomness: &[u8]) -> Result<(PublicKey, SecretKey)> {
        if randomness.len() != P::KEYGEN_RANDOM_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(keygen_with::<P>(MatrixGen::Aes128, randomness))
    }

    /// Key generation for set `P` from the RNG.
    ///
    /// # Errors
    ///
    /// Returns the RNG's error if it fails.
    pub fn keygen<P: FrodoParams>(rng: &mut impl CryptoRng) -> Result<(PublicKey, SecretKey)> {
        keygen_from_rng::<P>(MatrixGen::Aes128, rng)
    }

    /// Derandomized encapsulation for set `P`. See [`super::shake::encapsulate_derand`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `pk`, `mu` or `salt` has the wrong length.
    pub fn encapsulate_derand<P: FrodoParams>(
        pk: &[u8],
        mu: &[u8],
        salt: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        encapsulate_with::<P>(MatrixGen::Aes128, pk, mu, salt)
    }

    /// Encapsulation to `pk`, drawing `mu` and the salt from the RNG.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a malformed `pk`, or the RNG's error.
    pub fn encapsulate<P: FrodoParams>(
        pk: &PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        encapsulate_from_rng::<P>(MatrixGen::Aes128, pk, rng)
    }

    /// Decapsulation with implicit rejection.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `sk` or `ct` has the wrong length.
    pub fn decapsulate<P: FrodoParams>(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
        decapsulate_with::<P>(MatrixGen::Aes128, sk, ct)
    }
}
