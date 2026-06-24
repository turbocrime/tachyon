//! Public (verification) keys.

use derive_more::{Debug, Display, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::{EpAffine, group::GroupEncoding as _};

use crate::{action, action::Action, bundle, reddsa, value};

/// The randomized action verification key `rk` — per-action, public.
///
/// This is the only key type that **can verify** action signatures.
/// Goes into [`Action`](crate::Action). Terminal type — no further
/// derivation.
///
/// Both spend and output actions produce an `rk`
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// - **Spend**: $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ — requires
///   knowledge of $\mathsf{ask}$
/// - **Output**: $\mathsf{rk} = [\alpha]\,\mathcal{G}$ — no spending authority
///   needed
///
/// This unification lets consensus treat all actions identically while
/// the type system enforces the authority boundary at construction time.
#[derive(Clone, Copy, Debug, Display, From, Into, PartialEq, TotalEq)]
#[display("ActionVerificationKey({:x?})", self.0.to_bytes())]
pub struct ActionVerificationKey(EpAffine);

impl ActionVerificationKey {
    /// Verify an action signature against a transaction sighash.
    pub fn verify(&self, sighash: &[u8; 32], sig: &action::Signature) -> Result<(), reddsa::Error> {
        reddsa::VerificationKey::<reddsa::ActionAuth>::try_from(self.0.to_bytes())?
            .verify(sighash, &sig.0)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<reddsa::VerificationKey<reddsa::ActionAuth>> for ActionVerificationKey {
    fn into(self) -> reddsa::VerificationKey<reddsa::ActionAuth> {
        #[expect(clippy::expect_used, reason = "specified behavior")]
        reddsa::VerificationKey::<reddsa::ActionAuth>::try_from(self.0.to_bytes())
            .expect("curve point is a valid verification key")
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<reddsa::VerificationKeyBytes<reddsa::ActionAuth>> for ActionVerificationKey {
    fn into(self) -> reddsa::VerificationKeyBytes<reddsa::ActionAuth> {
        reddsa::VerificationKeyBytes::<reddsa::ActionAuth>::from(self.0.to_bytes())
    }
}

/// Derive the binding verification key from public bundle data.
///
/// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
///
/// The result should equal $[\mathsf{bsk}]\,\mathcal{R}$ if the signer
/// constructed the bundle correctly, similar to Orchard's binding key
/// derivation (Protocol §4.14)
#[must_use]
pub fn derive_bvk(
    action_cvs: impl Iterator<Item = value::Commitment>,
    value_balance: i64,
) -> EpAffine {
    let cv_sum: value::Commitment = action_cvs.sum();
    let cb0 = value::Commitment::balance(value_balance);
    EpAffine::from(cv_sum - cb0)
}

/// Binding verification key $\mathsf{bvk}$ — derived from value
/// commitments.
///
/// $$\mathsf{bvk} := \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
///
/// That is: sum all action value commitments (Pallas curve points),
/// then subtract the deterministic commitment to the value balance
/// with zero randomness. This key is **not encoded in the
/// transaction** — validators recompute it from public data (§4.14).
///
/// When the transaction is correctly constructed,
/// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$ because the
/// $\mathcal{V}$-component cancels
/// ($\sum_i v_i = \mathsf{v\_{balance}}$), leaving only the
/// $\mathcal{R}$-component
/// $[\sum_i \mathsf{rcv}_i]\,\mathcal{R} = [\mathsf{bsk}]\,\mathcal{R}$.
///
/// A validator checks balance by verifying:
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\mathsf{sighash},
///   \text{bindingSig}) = 1$
///
/// ## Type representation
///
/// Wraps `reddsa::VerificationKey<reddsa::BindingAuth>`, which internally
/// stores a Pallas curve point (EpAffine, encoded as 32 compressed bytes).
#[derive(Clone, Copy, Debug, Display, From, Into, PartialEq, TotalEq)]
#[display("BindingVerificationKey({:x?})", self.0.to_bytes())]
pub struct BindingVerificationKey(EpAffine);

impl BindingVerificationKey {
    /// Derive the binding verification key from public action data.
    ///
    /// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
    ///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
    ///
    /// This is the validator-side derivation similar to Orchard. (§4.14). The
    /// result should equal $[\mathsf{bsk}]\,\mathcal{R}$ when the signer
    /// constructed the bundle correctly.
    #[must_use]
    pub fn derive(actions: &[Action], value_balance: i64) -> Self {
        let cvs = actions.iter().map(|action| action.cv);
        Self::from(derive_bvk(cvs, value_balance))
    }

    /// Verify a binding signature against a transaction sighash.
    pub fn verify(&self, sighash: &[u8; 32], sig: &bundle::Signature) -> Result<(), reddsa::Error> {
        reddsa::VerificationKey::<reddsa::BindingAuth>::try_from(self.0.to_bytes())?
            .verify(sighash, &sig.0)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<reddsa::VerificationKey<reddsa::BindingAuth>> for BindingVerificationKey {
    fn into(self) -> reddsa::VerificationKey<reddsa::BindingAuth> {
        #[expect(clippy::expect_used, reason = "specified behavior")]
        reddsa::VerificationKey::<reddsa::BindingAuth>::try_from(self.0.to_bytes())
            .expect("curve point is a valid verification key")
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<reddsa::VerificationKeyBytes<reddsa::BindingAuth>> for BindingVerificationKey {
    fn into(self) -> reddsa::VerificationKeyBytes<reddsa::BindingAuth> {
        reddsa::VerificationKeyBytes::<reddsa::BindingAuth>::from(self.0.to_bytes())
    }
}
