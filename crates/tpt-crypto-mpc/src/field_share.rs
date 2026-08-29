//! Additive secret sharing over a prime field.
//!
//! A value `x` in `GF(p)` is shared among `n` parties as `n` uniformly random
//! field elements whose sum (mod `p`) equals `x`. Any `n-1` shares reveal nothing
//! about `x`; reconstruction is the field sum of the shares.

use alloc::vec::Vec;

use tpt_crypto_core::{CryptoRng, Error, Result};
use tpt_crypto_field::{Field, FieldElement, FieldParams, MAX_LIMBS};

/// A field element that can be sampled uniformly at random.
///
/// Implemented for [`FieldElement`] by rejection sampling against the canonical
/// encoding. Higher-layer code (extension towers) can provide their own sampler.
pub trait SampleField: Field {
    /// Sample a uniformly random element of the field using `rng`.
    fn random<R: CryptoRng>(rng: &mut R) -> Self;
}

impl<P: FieldParams> SampleField for FieldElement<P> {
    fn random<R: CryptoRng>(rng: &mut R) -> Self {
        let mut buf = [0u8; MAX_LIMBS * 8];
        loop {
            rng.fill_bytes(&mut buf);
            let opt = FieldElement::<P>::from_bytes(&buf);
            if opt.is_some().into_bool() {
                return opt.unwrap();
            }
        }
    }
}

/// Canonical byte serialization for a field element, used to carry shares and
/// Beaver-triple components across oblivious transfer.
pub trait FieldCodec: Field {
    /// Encode the element to its canonical fixed-width byte encoding.
    fn encode(&self) -> Vec<u8>;
    /// Decode a canonical encoding; returns `None` if the input is invalid.
    fn decode(bytes: &[u8]) -> Option<Self>;
}

impl<P: FieldParams> FieldCodec for FieldElement<P> {
    fn encode(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn decode(bytes: &[u8]) -> Option<Self> {
        let o = Self::from_bytes(bytes);
        if o.is_some().into_bool() {
            Some(o.unwrap())
        } else {
            None
        }
    }
}

/// One additive share of a secret field element.
///
/// Shares are meant to be held by distinct parties; this newtype only marks the
/// value as a share and provides the constant-time local operations a party can
/// perform on its own shares without interacting with the other parties.
#[derive(Clone, Copy, Debug)]
pub struct Share<F> {
    /// The field element held by this share's owner.
    pub value: F,
}

impl<F: Field> Share<F> {
    /// Wrap a field element as a share.
    pub fn new(value: F) -> Self {
        Share { value }
    }

    /// Local addition of two shares of the *same* secret: `(a + b)` is a share of
    /// `x + y` when `a`, `b` are shares of `x`, `y`. Constant-time.
    pub fn add(&self, other: &Self) -> Self {
        Share::new(self.value.add(&other.value))
    }

    /// Local subtraction of two shares of the same secret. Constant-time.
    pub fn sub(&self, other: &Self) -> Self {
        Share::new(self.value.sub(&other.value))
    }

    /// Local multiplication of a share by a *public* scalar `c`: `c * a` is a share
    /// of `c * x`. Constant-time.
    pub fn scale(&self, c: &F) -> Self {
        Share::new(self.value.mul(c))
    }

    /// Local additive inverse of a share. Constant-time.
    pub fn neg(&self) -> Self {
        Share::new(self.value.neg())
    }
}

impl<F: Field> From<F> for Share<F> {
    fn from(value: F) -> Self {
        Share::new(value)
    }
}

/// Share `x` among `n >= 2` parties: returns `n` shares whose field sum equals `x`.
///
/// The first `n-1` shares are uniformly random; the final share is fixed as
/// `x - sum(other shares)`, so reconstruction is exact.
pub fn share_secret<F, R>(rng: &mut R, x: &F, n: usize) -> Result<Vec<Share<F>>>
where
    F: SampleField + Field,
    R: CryptoRng,
{
    if n < 2 {
        return Err(Error::InvalidLength);
    }
    let mut shares = Vec::with_capacity(n);
    let mut sum = F::zero();
    for _ in 0..n - 1 {
        let s = F::random(rng);
        sum = sum.add(&s);
        shares.push(Share::new(s));
    }
    shares.push(Share::new(x.sub(&sum)));
    Ok(shares)
}

/// Two-party additive sharing of `x`: returns `(x - r, r)` for a uniform `r`.
pub fn share_secret_2<F, R>(rng: &mut R, x: &F) -> (Share<F>, Share<F>)
where
    F: SampleField + Field,
    R: CryptoRng,
{
    let r = F::random(rng);
    let s0 = Share::new(x.sub(&r));
    let s1 = Share::new(r);
    (s0, s1)
}

/// Reconstruct the secret from additive shares by summing them in the field.
///
/// Constant-time in the share values (field addition is branch-free).
pub fn reconstruct<F: Field>(shares: &[Share<F>]) -> F {
    let mut acc = F::zero();
    for s in shares {
        acc = acc.add(&s.value);
    }
    acc
}
