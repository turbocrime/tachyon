//! Extractor role: assemble a fully-authorized Stamped bundle.

use alloc::vec::Vec;
use core::{error::Error, fmt};

use super::PartialBundle;
use crate::{action, bundle, stamp::Stamp};

impl PartialBundle {
    /// Assemble a fully-authorized [`Stamped`](crate::Stamped) bundle.
    ///
    /// Requires all actions to have signatures, a binding signature,
    /// and a stamp. Derives value_balance from notes.
    pub fn extract(self) -> Result<bundle::Bundle<Stamp>, ExtractError> {
        let value_balance = self.value_balance();
        let binding_sig = self.binding_sig.ok_or(ExtractError::MissingBindingSig)?;
        let stamp = self.stamp.ok_or(ExtractError::MissingStamp)?;

        let mut actions = Vec::with_capacity(self.spends.len() + self.outputs.len());

        for spend in self.spends {
            let sig = spend.sig.ok_or(ExtractError::MissingActionSig)?;
            actions.push(action::Action {
                cv: spend.cv,
                rk: spend.rk,
                sig,
            });
        }

        for output in self.outputs {
            let sig = output.sig.ok_or(ExtractError::MissingActionSig)?;

            actions.push(action::Action {
                cv: output.cv,
                rk: output.rk,
                sig,
            });
        }

        // TODO: validate signatures

        Ok(bundle::Bundle {
            actions,
            value_balance,
            binding_sig,
            stamp,
        })
    }
}

/// Errors from the Extractor role.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExtractError {
    /// An action is missing a signature.
    MissingActionSig,
    /// The bundle is missing the binding signature.
    MissingBindingSig,
    /// Bundle is missing the stamp proof.
    MissingStamp,
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::MissingActionSig => write!(f, "missing action signature"),
            | Self::MissingBindingSig => write!(f, "missing binding signature"),
            | Self::MissingStamp => write!(f, "missing stamp"),
        }
    }
}

impl Error for ExtractError {}
