//! Tachyon Action descriptions.

use reddsa::orchard::SpendAuth;

use crate::{
    entropy::ActionEntropy,
    keys::{SpendValidatingKey, private, public},
    note::Note,
    value,
};

/// Whether an action plan represents a spend or an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Spend — signed with
    /// [`SpendAuthorizingKey::derive_action_private`](private::SpendAuthorizingKey::derive_action_private).
    Spend,
    /// Output — signed via
    /// [`ActionSigningKey<Output>::sign`](private::ActionSigningKey::sign).
    Output,
}

/// A planned Tachyon action, not yet authorized.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,
    /// The note being spent or created.
    pub note: Note,
    /// Per-action entropy for alpha derivation.
    pub theta: ActionEntropy,
    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,
    /// Spend or output.
    pub effect: Effect,
}

impl Plan {
    /// Assemble a spend action plan.
    ///
    /// $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn spend(
        note: Note,
        theta: ActionEntropy,
        rcv: value::CommitmentTrapdoor,
        ak: &SpendValidatingKey,
    ) -> Self {
        let cm = note.commitment();
        let alpha = theta.spend_randomizer(&cm);
        let rk = ak.derive_action_public(&alpha);

        Self {
            rk,
            note,
            theta,
            rcv,
            effect: Effect::Spend,
        }
    }

    /// Assemble an output action plan.
    ///
    /// $\mathsf{rk} = [\alpha]\,\mathcal{G}$.
    #[must_use]
    pub fn output(note: Note, theta: ActionEntropy, rcv: value::CommitmentTrapdoor) -> Self {
        let cm = note.commitment();
        let alpha = theta.output_randomizer(&cm);
        let rsk = private::ActionSigningKey::new(alpha);
        let rk = rsk.derive_action_public();

        Self {
            rk,
            note,
            theta,
            rcv,
            effect: Effect::Output,
        }
    }

    /// Derive the value commitment of this action plan.
    ///
    /// $$\mathsf{cv} = [\pm v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    #[must_use]
    pub fn cv(&self) -> value::Commitment {
        match self.effect {
            | Effect::Spend => self.rcv.commit_spend(self.note),
            | Effect::Output => self.rcv.commit_output(self.note),
        }
    }
}

/// An authorized Tachyon action.
///
/// - `cv`: Commitment to a value effect
/// - `rk`: Public key (randomized counterpart to `rsk`)
/// - `sig`: Signature (by single-use `rsk`) over transaction sighash
///
/// ## Note
///
/// The tachygram (nullifier or note commitment) is NOT part of the action.
/// Tachygrams are collected separately in the [`Stamp`](crate::Stamp).
/// However, `rk` is not a direct input to the Ragu proof -- each `rk` is
/// cryptographically bound to its corresponding tachygram, which *is* a proof
/// input, so the proof validates `rk` transitively.
///
/// This separation allows the stamp to be stripped during aggregation
/// while the action (with its authorization) remains in the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Action {
    /// Value commitment $\mathsf{cv} = [v]\,\mathcal{V}
    /// + [\mathsf{rcv}]\,\mathcal{R}$ (EpAffine).
    pub cv: value::Commitment,

    /// Randomized action verification key $\mathsf{rk}$ (EpAffine).
    pub rk: public::ActionVerificationKey,

    /// RedPallas spend auth signature over the transaction sighash.
    pub sig: Signature,
}

/// A spend authorization signature (RedPallas over SpendAuth).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct Signature(pub(crate) reddsa::Signature<SpendAuth>);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(reddsa::Signature::<SpendAuth>::from(bytes))
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        <[u8; 64]>::from(sig.0)
    }
}

// Custom serde implementation for Signature
#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: [u8; 64] = (*self).into();
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
#[expect(clippy::missing_trait_methods, reason = "serde defaults are correct")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de;

        struct ByteArrayVisitor;

        #[expect(clippy::missing_trait_methods, reason = "serde defaults are correct")]
        impl de::Visitor<'_> for ByteArrayVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() == 64 {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(v);
                    Ok(bytes)
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }
        }

        let bytes = deserializer.deserialize_bytes(ByteArrayVisitor)?;
        Ok(Self::from(bytes))
    }
}
