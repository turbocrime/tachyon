use alloc::vec::Vec;

use derive_more::{Debug, Display, Error};
use rand_core::CryptoRng;
use udon::field::Field as _;

use super::{
    ActionWitness, Bundle, MissingField, NoteField, OpeningCheckError, OpeningField, VerifyError,
};
use crate::{
    Note, action,
    keys::{private, public},
    pasta::Fp,
    primitives::effect,
};

/// The opening under examination.
#[derive(Clone, Copy, Debug, Display)]
pub enum OpeningLocation {
    /// An indexed action.
    #[display("action {_0}")]
    Action(usize),
    /// The maximum fee note.
    MaxFee,
}

/// An invalid opening.
#[derive(Clone, Copy, Debug, Display)]
pub enum OpeningReason {
    /// The action randomness is not representable.
    Randomness,
    /// The note commitment trapdoor is zero.
    ZeroRcm,
    /// The opening does not derive the stored effect.
    Mismatch,
}

/// The IO Finalizer cannot derive consistent authorizing data.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum IoFinalizerError {
    /// A required input is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] MissingField),
    /// An opening is invalid.
    #[display("invalid opening for {_0}: {_1}")]
    Opening(
        #[error(not(source))] OpeningLocation,
        #[error(not(source))] OpeningReason,
    ),
    /// The trapdoor sum does not match the effects.
    #[display("binding key mismatch")]
    BindingKeyMismatch,
    /// A stored signature does not verify.
    #[display("invalid stored signature at action {_0}")]
    InvalidStoredSignature(#[error(not(source))] usize),
}

/// An action cannot accept a signature.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum SignError {
    /// The action index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The witness or owner is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] MissingField),
    /// The action is not a spend.
    #[display("action is not a spend")]
    NotSpend,
    /// The key does not own the action.
    #[display("wrong spend owner")]
    WrongOwner,
    /// Opening verification failed.
    #[display("invalid spend opening")]
    Opening(VerifyError),
    /// The stored signature does not verify.
    #[display("invalid stored signature")]
    InvalidStoredSignature,
}

/// Failure to import a signature.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum ApplySignatureError {
    /// The action index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The supplied signature does not verify.
    #[display("invalid signature")]
    InvalidSignature,
    /// A different signature already occupies the slot.
    #[display("conflicting signature")]
    Conflict,
}

pub(super) enum FeeOpeningError {
    Missing(NoteField),
    ZeroRcm,
    CommitmentMismatch,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "signing roles are defined together"
)]
impl Bundle {
    pub(super) fn checked_fee_opening(&self) -> Result<Note, FeeOpeningError> {
        let note = self
            .max_fee
            .note
            .complete()
            .map_err(FeeOpeningError::Missing)?;
        if Fp::from(note.rcm) == Fp::ZERO {
            return Err(FeeOpeningError::ZeroRcm);
        }
        if note.cv_feemax() != self.max_fee.cv_feemax {
            return Err(FeeOpeningError::CommitmentMismatch);
        }
        Ok(note)
    }

    pub(super) fn binding_key_matches(&self, bsk: &private::BindingSigningKey) -> bool {
        bsk.derive_binding_public()
            == public::BindingVerificationKey::derive(
                self.actions
                    .iter()
                    .map(|action| action.descriptor.cv)
                    .chain([self.max_fee.cv_feemax]),
                self.value_balance,
            )
    }

    /// Establish the binding key and authorize the outputs.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or inconsistent input data.
    pub fn finalize_io<RNG: CryptoRng>(
        &mut self,
        sighash: [u8; 32],
        rng: &mut RNG,
    ) -> Result<(), IoFinalizerError> {
        let fee_note = self.checked_fee_opening().map_err(|err| match err {
            FeeOpeningError::Missing(field) => {
                IoFinalizerError::Missing(MissingField::MaxFee(field))
            },
            FeeOpeningError::ZeroRcm => {
                IoFinalizerError::Opening(OpeningLocation::MaxFee, OpeningReason::ZeroRcm)
            },
            FeeOpeningError::CommitmentMismatch => {
                IoFinalizerError::Opening(OpeningLocation::MaxFee, OpeningReason::Mismatch)
            },
        })?;
        let mut blinds = Vec::with_capacity(self.actions.len() + 1);
        for (index, action) in self.actions.iter().enumerate() {
            blinds.push(
                action
                    .rcv
                    .ok_or(IoFinalizerError::Missing(MissingField::Action(
                        index,
                        OpeningField::Rcv,
                    )))?,
            );
        }
        blinds.push(fee_note.derive_feemax_blind());
        let bsk = private::BindingSigningKey::from(blinds);
        if !self.binding_key_matches(&bsk)
            || self.bsk.is_some_and(|key| key.to_bytes() != bsk.to_bytes())
        {
            return Err(IoFinalizerError::BindingKeyMismatch);
        }
        let mut sigs = Vec::with_capacity(self.actions.len());
        for (index, action) in self.actions.iter().enumerate() {
            let missing = |field| IoFinalizerError::Missing(MissingField::Action(index, field));
            let witness = action
                .witness
                .as_ref()
                .ok_or_else(|| missing(OpeningField::Witness))?;
            let sig = match *witness {
                ActionWitness::Spend(_) => None,
                ActionWitness::Output(_) => {
                    let opening = action.opening::<effect::Output>(()).map_err(missing)?;
                    let checked = opening.check().map_err(|err| {
                        IoFinalizerError::Opening(
                            OpeningLocation::Action(index),
                            match err {
                                OpeningCheckError::ZeroRcm => OpeningReason::ZeroRcm,
                                OpeningCheckError::Randomness => OpeningReason::Randomness,
                            },
                        )
                    })?;
                    if checked.descriptor != action.descriptor {
                        return Err(IoFinalizerError::Opening(
                            OpeningLocation::Action(index),
                            OpeningReason::Mismatch,
                        ));
                    }
                    if let Some(stored) = action.sig {
                        action
                            .descriptor
                            .rk
                            .verify(&sighash, &stored)
                            .map_err(|_err| IoFinalizerError::InvalidStoredSignature(index))?;
                        sigs.push(None);
                        continue;
                    }
                    Some(private::ActionSigningKey::new(&checked.alpha).sign(rng, &sighash))
                },
            };
            sigs.push(sig);
        }
        for (action, sig) in self.actions.iter_mut().zip(sigs) {
            if sig.is_some() {
                action.sig = sig;
            }
        }
        self.bsk = Some(bsk);
        Ok(())
    }

    /// Sign one owned spend. For full bundle review, use [`Self::plan`] first.
    ///
    /// # Errors
    ///
    /// Returns an error if the indexed action is not a fully opened spend of
    /// `ask`, or if its descriptor does not match.
    #[expect(clippy::ref_patterns, reason = "borrow the spend witness")]
    pub fn sign_at<RNG: CryptoRng>(
        &mut self,
        index: usize,
        sighash: [u8; 32],
        ask: &private::SpendAuthorizingKey,
        rng: &mut RNG,
    ) -> Result<(), SignError> {
        let action = self
            .actions
            .get_mut(index)
            .ok_or(SignError::InvalidIndex(index))?;
        let Some(ref witness) = action.witness else {
            return Err(SignError::Missing(MissingField::Action(
                index,
                OpeningField::Witness,
            )));
        };
        let ActionWitness::Spend(ref spend) = *witness else {
            return Err(SignError::NotSpend);
        };
        let ak = ask.derive_auth_public();
        let owner = spend.ak.ok_or(SignError::Missing(MissingField::Action(
            index,
            OpeningField::Ak,
        )))?;
        if <[u8; 32]>::from(owner.0) != <[u8; 32]>::from(ak.0) {
            return Err(SignError::WrongOwner);
        }
        let opening = action
            .opening::<effect::Spend>(ak)
            .map_err(|field| SignError::Opening(VerifyError::Missing(field)))?;
        let checked = opening
            .check()
            .map_err(|err| {
                SignError::Opening(match err {
                    OpeningCheckError::ZeroRcm => VerifyError::ZeroRcm,
                    OpeningCheckError::Randomness => VerifyError::Randomness,
                })
            })?
            .matches(action.descriptor)
            .map_err(SignError::Opening)?;
        if let Some(stored) = action.sig {
            return action
                .descriptor
                .rk
                .verify(&sighash, &stored)
                .map_err(|_err| SignError::InvalidStoredSignature);
        }
        action.sig = Some(
            ask.derive_action_private(&checked.alpha)
                .sign(rng, &sighash),
        );
        Ok(())
    }

    /// Import a signature under the indexed descriptor's verification key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid index, invalid signature or conflict
    /// with the stored signature.
    pub fn apply_signature_at(
        &mut self,
        index: usize,
        sighash: [u8; 32],
        sig: action::Signature,
    ) -> Result<(), ApplySignatureError> {
        let action = self
            .actions
            .get_mut(index)
            .ok_or(ApplySignatureError::InvalidIndex(index))?;
        action
            .descriptor
            .rk
            .verify(&sighash, &sig)
            .map_err(|_err| ApplySignatureError::InvalidSignature)?;
        if action.sig.is_some_and(|stored| stored != sig) {
            return Err(ApplySignatureError::Conflict);
        }
        action.sig = Some(sig);
        Ok(())
    }
}
