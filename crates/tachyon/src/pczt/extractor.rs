use alloc::vec::Vec;

use derive_more::{Debug, Display, Error};
use rand_core::CryptoRng;

use super::{Bundle, Effects};
use crate::{Tachygram, action, fee, keys::private, stamp};

/// An absent field required for extraction.
#[derive(Clone, Copy, Debug, Display)]
pub enum ExtractionField {
    /// The binding signing key.
    #[display("binding key")]
    BindingKey,
    /// The fee-applied proof.
    #[display("fee-applied proof")]
    AutonomeParts,
    /// An indexed action's signature.
    #[display("signature at action {_0}")]
    Signature(usize),
}

/// The section cannot be extracted.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum TxExtractorError {
    /// Required authorization is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] ExtractionField),
    /// The binding key does not match the effects.
    #[display("binding key mismatch")]
    BindingKeyMismatch,
    /// Pair keys do not match the actions, or the stamp has adjuncts.
    #[display("invalid stamp coverage")]
    Coverage,
}

/// Complete authorizing data awaiting the transaction sighash.
#[derive(Debug)]
pub struct Unbound {
    effects: Effects,
    action_auth: Vec<(action::Signature, (Tachygram, Tachygram))>,
    parts: stamp::AutonomeParts,
    bsk: private::BindingSigningKey,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "extractor entry point is defined with its role"
)]
impl Bundle {
    /// Drop construction data and retain the effects and authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for missing authorization, mismatched pair coverage,
    /// an aggregate stamp or a mismatched binding key.
    pub fn extract(self) -> Result<Unbound, TxExtractorError> {
        let bsk = self
            .bsk
            .ok_or(TxExtractorError::Missing(ExtractionField::BindingKey))?;
        if !self.binding_key_matches(&bsk) {
            return Err(TxExtractorError::BindingKeyMismatch);
        }
        let effects = self.effects();
        let parts = self
            .autonome_parts
            .ok_or(TxExtractorError::Missing(ExtractionField::AutonomeParts))?;
        if !parts.stamp.adjuncts.is_empty() || !parts.pairs.keys().eq(effects.actions.iter()) {
            return Err(TxExtractorError::Coverage);
        }
        let action_auth = self
            .actions
            .into_iter()
            .enumerate()
            .map(|(index, action)| {
                Ok((
                    action
                        .sig
                        .ok_or(TxExtractorError::Missing(ExtractionField::Signature(index)))?,
                    *parts
                        .pairs
                        .get(&action.descriptor)
                        .ok_or(TxExtractorError::Coverage)?,
                ))
            })
            .collect::<Result<_, TxExtractorError>>()?;
        Ok(Unbound {
            effects,
            action_auth,
            parts,
            bsk,
        })
    }
}

impl Unbound {
    /// Bind the bundle to the transaction. The caller verifies the result.
    pub fn apply_binding_signature<RNG: CryptoRng>(
        self,
        sighash: [u8; 32],
        rng: &mut RNG,
    ) -> crate::Bundle<stamp::ProofStamp<stamp::Uncompressed>> {
        crate::Bundle {
            value_balance: self.effects.value_balance,
            actions: self.effects.actions,
            action_auth: self.action_auth,
            fee: fee::Descriptor {
                cv_feemax: self.effects.cv_feemax,
                v_fee: self.parts.fee,
            },
            fee_auth: self.parts.cm_change,
            memo: self.effects.memo,
            stamp: self.parts.stamp,
            binding_sig: self.bsk.sign(rng, &sighash),
        }
    }
}
