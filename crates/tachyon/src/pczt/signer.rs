//! Signer role: produce spend authorization signatures.

use core::{error::Error, fmt};

use rand_core::{CryptoRng, RngCore};

use super::PartialAction;
use crate::{
    action,
    keys::private::{ActionSigningKey, SpendAuthorizingKey},
    primitives::{Effect, effect},
};

impl PartialAction<effect::Spend> {
    /// Sign this spend action with a spend authorizing key.
    ///
    /// Derives alpha from theta + note commitment, then signs with
    /// the randomized spend key.
    pub fn sign(
        &mut self,
        sighash: &[u8; 32],
        ask: &SpendAuthorizingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), SignerError> {
        let cm = self.note.commitment();
        let alpha = self.theta.randomizer::<effect::Spend>(&cm);
        let rsk = ask.derive_action_private(&alpha);

        if rsk.derive_action_public() != self.rk {
            return Err(SignerError::RkMismatch);
        }

        self.sig = Some(rsk.sign(rng, sighash));
        Ok(())
    }
}

impl PartialAction<effect::Output> {
    /// Sign this output action.
    ///
    /// Output actions derive their signing key solely from alpha —
    /// no spend authority is required.
    pub fn sign(
        &mut self,
        sighash: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), SignerError> {
        let cm = self.note.commitment();
        let alpha = self.theta.randomizer::<effect::Output>(&cm);
        let rsk = ActionSigningKey::new(&alpha);

        if rsk.derive_action_public() != self.rk {
            return Err(SignerError::RkMismatch);
        }

        self.sig = Some(rsk.sign(rng, sighash));
        Ok(())
    }
}

impl<E: Effect> PartialAction<E> {
    /// Apply an externally-produced signature (e.g. from FROST).
    ///
    /// Validates the signature against rk and sighash before accepting.
    pub fn apply_signature(
        &mut self,
        sighash: &[u8; 32],
        sig: action::Signature,
    ) -> Result<(), SignerError> {
        self.rk
            .verify(sighash, &sig)
            .map_err(|_err| SignerError::InvalidSignature)?;

        self.sig = Some(sig);
        Ok(())
    }
}

/// Errors from the Signer role.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignerError {
    /// Derived rk does not match the stored rk.
    RkMismatch,
    /// An externally-provided signature failed verification.
    InvalidSignature,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::RkMismatch => write!(f, "derived rk does not match stored rk"),
            | Self::InvalidSignature => write!(f, "invalid external signature"),
        }
    }
}

impl Error for SignerError {}
