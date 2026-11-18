//! Compile-time effect markers for spend vs output actions.
//!
//! [`Spend`] and [`Output`] are zero-sized marker types that parameterize
//! [`Plan`](crate::action::Plan),
//! [`ActionRandomizer`],
//! [`ActionSigningKey`](crate::keys::private::ActionSigningKey), and key types
//! to enforce the spend/output distinction at compile time.

use udon::field::Field as _;

use crate::{
    digest::poseidon,
    entropy::{ActionEntropy, ActionRandomizer},
    keys::{SpendValidatingKey, private, public},
    note,
    pasta::{Fp, Fq},
    value,
};

/// Embeds a base-field element in the scalar field, which is larger.
#[expect(
    clippy::expect_used,
    reason = "p < q, so every Fp repr is canonical in Fq"
)]
fn embed(alpha: Fp) -> Fq {
    Fq::from_bytes(alpha.to_bytes()).expect("p < q")
}

mod sealed {
    pub trait Sealed: Copy {}
    impl Sealed for super::Spend {}
    impl Sealed for super::Output {}
}

/// Sealed trait marking an action effect (spend or output).
pub trait Effect: sealed::Sealed {
    /// The spend owner, or `()` for an output.
    type Authority: Copy;

    /// Derive the action verification key from its randomizer and authority.
    fn derive_rk(
        authority: &Self::Authority,
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey;

    /// Derive this effect's $\alpha$ scalar from per-action entropy and a note
    /// commitment.
    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq;

    /// Commit to this effect's signed value contribution using the given
    /// trapdoor.
    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment;
}

/// Spend effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Output effect marker.
#[derive(Clone, Copy, Debug)]
pub struct Output;

impl Effect for Spend {
    type Authority = SpendValidatingKey;

    fn derive_rk(
        authority: &Self::Authority,
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey {
        authority.derive_action_public(alpha)
    }

    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        embed(poseidon::alpha_spend(theta.0, cm.into()))
    }

    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment {
        rcv.commit(value)
    }
}

impl Effect for Output {
    type Authority = ();

    fn derive_rk(
        _authority: &Self::Authority,
        alpha: &ActionRandomizer<Self>,
    ) -> public::ActionVerificationKey {
        private::ActionSigningKey::new(alpha).derive_action_public()
    }

    fn derive_alpha(theta: ActionEntropy, cm: note::Commitment) -> Fq {
        embed(poseidon::alpha_output(theta.0, cm.into()))
    }

    fn commit_value(rcv: value::Trapdoor, value: value::Positive) -> value::Commitment {
        rcv.commit(-value)
    }
}
