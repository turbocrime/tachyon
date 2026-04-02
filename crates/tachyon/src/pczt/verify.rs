//! Verification utilities for PCZT actions.

use core::{error::Error, fmt};

use super::PartialAction;
use crate::{
    keys::private::{ActionSigningKey, SpendAuthorizingKey},
    primitives::effect,
};

impl PartialAction<effect::Spend> {
    /// Verify that cv matches note + rcv for a spend.
    pub fn verify_cv(&self) -> Result<(), VerifyError> {
        let expected_cv = self.rcv.commit(i64::from(self.note.value));

        if expected_cv != self.cv {
            return Err(VerifyError::CvMismatch);
        }
        Ok(())
    }

    /// Verify that rk matches theta + note + ask for a spend.
    pub fn verify_rk(&self, ask: &SpendAuthorizingKey) -> Result<(), VerifyError> {
        let cm = self.note.commitment();
        let alpha = self.theta.randomizer::<effect::Spend>(&cm);
        let expected_rk = ask.derive_action_private(&alpha).derive_action_public();

        if expected_rk != self.rk {
            return Err(VerifyError::RkMismatch);
        }
        Ok(())
    }
}

impl PartialAction<effect::Output> {
    /// Verify that cv matches note + rcv for an output.
    pub fn verify_cv(&self) -> Result<(), VerifyError> {
        let expected_cv = self.rcv.commit(-i64::from(self.note.value));

        if expected_cv != self.cv {
            return Err(VerifyError::CvMismatch);
        }
        Ok(())
    }

    /// Verify that rk matches theta + note for an output.
    pub fn verify_rk(&self) -> Result<(), VerifyError> {
        let cm = self.note.commitment();
        let alpha = self.theta.randomizer::<effect::Output>(&cm);
        let expected_rk = ActionSigningKey::new(&alpha).derive_action_public();

        if expected_rk != self.rk {
            return Err(VerifyError::RkMismatch);
        }
        Ok(())
    }
}

/// Errors from verification.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// Computed cv does not match stored cv.
    CvMismatch,
    /// Computed rk does not match stored rk.
    RkMismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::CvMismatch => write!(f, "cv does not match note + rcv"),
            | Self::RkMismatch => write!(f, "rk does not match theta + ask"),
        }
    }
}

impl Error for VerifyError {}
