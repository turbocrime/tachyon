//! IO Finalizer role: compute binding signing key, verify value
//! commitment consistency, and sign.
#![allow(clippy::similar_names, reason = "meaningful names")]

extern crate alloc;

use alloc::vec::Vec;
use core::{error::Error, fmt};

use rand_core::{CryptoRng, RngCore};

use super::PartialBundle;
use crate::{
    keys::{private, public, public::derive_bvk},
    value,
};

impl PartialBundle {
    /// Compute the binding signing key from rcv values, verify that
    /// the value commitments are consistent with value_balance, and
    /// create the binding signature.
    pub fn finalize_io(
        &mut self,
        sighash: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), IoFinalizerError> {
        let (action_cvs, action_rcvs): (Vec<value::Commitment>, Vec<value::CommitmentTrapdoor>) = {
            let spends = self.spends.iter().map(|action| (action.cv, action.rcv));
            let outputs = self.outputs.iter().map(|action| (action.cv, action.rcv));
            spends.chain(outputs).unzip()
        };

        // Derive the binding signing key from rcv trapdoors.
        //    bsk = Σ rcv_i  (scalar sum in Fq)
        let bsk = private::BindingSigningKey::from(action_rcvs.as_slice());

        // Verify that the public cv values are consistent with the
        // rcv trapdoors and value_balance.
        //
        //    bvk_from_cvs  = Σ cv_i − [v_balance]V   (from public data)
        //    bvk_from_bsk  = [bsk]R                   (from private rcvs)
        //
        // These must be equal. If not, either a cv was tampered or
        // value_balance is wrong.

        let confirm_bvk = public::BindingVerificationKey::from(derive_bvk(
            action_cvs.into_iter(),
            self.value_balance(),
        ));

        if confirm_bvk != bsk.derive_binding_public() {
            return Err(IoFinalizerError::BvkMismatch);
        }

        // Sign the binding signature.
        self.binding_sig = Some(bsk.sign(rng, sighash));
        Ok(())
    }
}

/// Errors from the IO Finalizer role.
#[derive(Debug)]
#[non_exhaustive]
pub enum IoFinalizerError {
    /// The action value commitments seem to be inconsistent with the trapdoors
    /// and public balance, so the binding verification key does not compute
    /// consistently.
    BvkMismatch,
}

impl fmt::Display for IoFinalizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::BvkMismatch => {
                write!(f, "bvk mismatch indicates value commitment inconsistency")
            },
        }
    }
}

impl Error for IoFinalizerError {}
