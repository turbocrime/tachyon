//! Parse boundary: validated constructors from raw byte arrays.
//!
//! These constructors convert untrusted byte data (e.g. from a future
//! serialization crate) into typed domain objects. Each field is
//! independently validated; no cross-field checks are performed here
//! (that's [`verify`](super::verify)'s job).

#![allow(clippy::similar_names, reason = "meaningful names")]

extern crate alloc;

use alloc::vec::Vec;
use core::{error::Error, fmt, marker::PhantomData};

use ff::PrimeField as _;
use pasta_curves::Fp;

use super::{PartialAction, PartialBundle};
use crate::{
    action, bundle,
    constants::NOTE_VALUE_MAX,
    entropy::ActionEntropy,
    keys::{PaymentKey, public},
    note::{self, Note},
    primitives::{Anchor, Effect, Epoch, effect},
    value,
};

/// Raw note fields as byte arrays, for use by a serialization layer.
#[derive(Clone, Copy, Debug)]
pub struct RawNote {
    /// Payment key (Fp, 32 bytes).
    pub pk: [u8; 32],
    /// Note value in zatoshis.
    pub value: u64,
    /// Nullifier trapdoor (Fp, 32 bytes).
    pub psi: [u8; 32],
    /// Note commitment trapdoor (Fp, 32 bytes).
    pub rcm: [u8; 32],
}

impl<E: Effect> PartialAction<E> {
    /// Parse a partial action from raw byte arrays.
    ///
    /// Validates each field independently. Returns [`ParseError`] if
    /// any byte array does not encode a valid cryptographic object.
    pub fn parse(
        raw_cv: [u8; 32],
        raw_rk: [u8; 32],
        raw_note: RawNote,
        raw_theta: [u8; 32],
        raw_rcv: [u8; 32],
        raw_sig: Option<[u8; 64]>,
    ) -> Result<Self, ParseError> {
        let cv = value::Commitment::from_bytes(raw_cv).ok_or(ParseError::InvalidCv)?;
        let rk = public::ActionVerificationKey::try_from(raw_rk)
            .map_err(|_err| ParseError::InvalidRk)?;
        let note = parse_note(raw_note)?;
        let theta = ActionEntropy::from_bytes(raw_theta);
        let rcv = value::CommitmentTrapdoor::from_bytes(raw_rcv).ok_or(ParseError::InvalidRcv)?;
        let sig = raw_sig.map(action::Signature::from);

        Ok(Self {
            cv,
            rk,
            note,
            theta,
            rcv,
            sig,
            _effect: PhantomData,
        })
    }
}

impl PartialBundle {
    /// Parse a partial bundle from pre-parsed actions and raw
    /// bundle-level fields.
    ///
    /// Actions should already be parsed via [`PartialAction::parse`].
    /// Bundle-level byte arrays (anchor, binding_sig) are validated here.
    ///
    /// Stamp parsing is not yet supported — pass `None`.
    pub fn parse(
        parsed_spends: Vec<PartialAction<effect::Spend>>,
        parsed_outputs: Vec<PartialAction<effect::Output>>,
        raw_anchor: Option<[u8; 32]>,
        raw_epoch: Option<u32>,
        raw_binding_sig: Option<[u8; 64]>,
    ) -> Result<Self, ParseError> {
        let anchor = raw_anchor
            .map(|bytes| Anchor::from_bytes(bytes).ok_or(ParseError::InvalidAnchor))
            .transpose()?;

        let epoch = raw_epoch.map(Epoch::from);

        let binding_sig = raw_binding_sig.map(bundle::Signature::from);

        Ok(Self {
            spends: parsed_spends,
            outputs: parsed_outputs,
            anchor,
            epoch,
            binding_sig,
            stamp: None,
        })
    }
}

/// Parse a [`RawNote`] into a typed [`Note`].
fn parse_note(raw: RawNote) -> Result<Note, ParseError> {
    let pk = Fp::from_repr(raw.pk)
        .into_option()
        .map(PaymentKey)
        .ok_or(ParseError::InvalidNotePk)?;

    if raw.value > NOTE_VALUE_MAX {
        return Err(ParseError::InvalidNoteValue);
    }
    let value = note::Value(raw.value);

    let psi = Fp::from_repr(raw.psi)
        .into_option()
        .map(note::NullifierTrapdoor::from)
        .ok_or(ParseError::InvalidNotePsi)?;

    let rcm = Fp::from_repr(raw.rcm)
        .into_option()
        .map(note::CommitmentTrapdoor::from)
        .ok_or(ParseError::InvalidNoteRcm)?;

    Ok(Note {
        pk,
        value,
        psi,
        rcm,
    })
}

/// Errors from parsing raw bytes into PCZT types.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// cv bytes are not a valid Pallas affine point.
    InvalidCv,
    /// rk bytes are not a valid RedPallas verification key.
    InvalidRk,
    /// Note payment key bytes are not a valid Fp element.
    InvalidNotePk,
    /// Note value exceeds NOTE_VALUE_MAX.
    InvalidNoteValue,
    /// Note nullifier trapdoor bytes are not a valid Fp element.
    InvalidNotePsi,
    /// Note commitment trapdoor bytes are not a valid Fp element.
    InvalidNoteRcm,
    /// Rcv bytes are not a valid Fq scalar.
    InvalidRcv,
    /// Anchor bytes are not a valid Fp element.
    InvalidAnchor,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::InvalidCv => write!(f, "invalid value commitment"),
            | Self::InvalidRk => write!(f, "invalid action verification key"),
            | Self::InvalidNotePk => write!(f, "invalid note payment key"),
            | Self::InvalidNoteValue => write!(f, "note value exceeds maximum"),
            | Self::InvalidNotePsi => write!(f, "invalid note nullifier trapdoor"),
            | Self::InvalidNoteRcm => write!(f, "invalid note commitment trapdoor"),
            | Self::InvalidRcv => write!(f, "invalid value commitment trapdoor"),
            | Self::InvalidAnchor => write!(f, "invalid anchor"),
        }
    }
}

impl Error for ParseError {}
