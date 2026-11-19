//! Byte fields for a transaction container to carry and redact independently.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use corez::io;
use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use ragu::{ProductionRank, Rank as _};
use udon::{curve::Affine as _, field::Field as _};

use super::{
    self as pczt, DescriptorError, MissingField, NoteField, OpeningField, SpendKeyError,
    Zip32Derivation,
};
use crate::{
    Anchor, CompactSize, EpochIndex, Note, Tachygram, action,
    constants::EPOCH_MAX,
    entropy::ActionEntropy,
    keys::{NoteMasterKey, NullifierKey, ProofAuthorizingKey, SpendValidatingKey, private},
    pasta::{EpAffine, Fp, Fq},
    reddsa, serialization,
    stamp::{
        self,
        proof::{delegation, pool, spendable},
    },
    value,
};

/// The section's mirror. Absent effects require sufficient opening fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Bundle(..)")]
pub struct Bundle {
    /// Actions in commitment order.
    pub actions: Vec<Action>,
    /// The signed balance in zatoshis.
    pub value_balance: Option<i64>,
    /// Maximum fee data.
    pub max_fee: MaxFee,
    /// The memo.
    pub memo: Vec<u8>,
    /// Canonical proving anchor.
    pub anchor: Option<[u8; 32]>,
    /// Disjoint proofs before the fee.
    pub actions_proofs: Vec<ActionsProof>,
    /// Fee-applied proving data.
    pub autonome_parts: Option<AutonomeParts>,
    /// Canonical binding signing scalar.
    pub bsk: Option<[u8; 32]>,
    /// Bundle metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// The per-action byte fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Action(..)")]
pub struct Action {
    /// The action descriptor in its canonical encoding.
    pub descriptor: Option<[u8; 64]>,
    /// Authorization signature.
    pub sig: Option<[u8; 64]>,
    /// Independently redactable note fields.
    pub note: NoteOpening,
    /// Canonical action entropy.
    pub theta: Option<[u8; 32]>,
    /// Canonical value commitment trapdoor.
    pub rcv: Option<[u8; 32]>,
    /// Fields specific to the kind of action.
    pub witness: Option<ActionWitness>,
    /// Action metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// A note opening's byte fields.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
#[debug("NoteOpening(..)")]
pub struct NoteOpening {
    /// The payment key.
    pub pk: Option<[u8; 32]>,
    /// The value in zatoshis.
    pub value: Option<u64>,
    /// The nullifier trapdoor.
    pub psi: Option<[u8; 32]>,
    /// The commitment trapdoor.
    pub rcm: Option<[u8; 32]>,
}

/// Action-kind-specific byte fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
pub enum ActionWitness {
    /// A spend.
    Spend(SpendWitness),
    /// An output.
    Output(OutputWitness),
}

/// Spend authority and delegated proving fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("SpendWitness(..)")]
pub struct SpendWitness {
    /// The canonical spend validating key.
    pub ak: Option<[u8; 32]>,
    /// The spend validating key and nullifier key, in that order.
    pub pak: Option<[[u8; 32]; 2]>,
    /// The predecessor proofs and their carried data.
    pub lineage: Option<SpendLineage>,
    /// The key locator.
    pub zip32_derivation: Option<Zip32Derivation>,
}

/// Byte fields for the predecessor proofs of a spend.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("SpendLineage(..)")]
pub struct SpendLineage {
    /// Note secret proof and its commitment, note and master key.
    pub secret: Vec<u8>,
    /// Spendable proof and its commitment, epoch and anchor.
    pub spendable: Vec<u8>,
    /// Span proofs with their start and end anchors.
    pub spans: Vec<Vec<u8>>,
}

/// Recipient metadata for display and change recognition.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("OutputWitness(..)")]
pub struct OutputWitness {
    /// The key locator.
    pub zip32_derivation: Option<Zip32Derivation>,
    /// An unauthenticated address for display.
    pub user_address: Option<String>,
}

/// Maximum fee byte fields.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("MaxFee(..)")]
pub struct MaxFee {
    /// The canonical value commitment.
    pub cv_feemax: Option<[u8; 32]>,
    /// Independently redactable note fields.
    pub note: NoteOpening,
    /// The change recipient's key locator.
    pub zip32_derivation: Option<Zip32Derivation>,
    /// Fee metadata.
    pub proprietary: BTreeMap<String, Vec<u8>>,
}

/// A descriptor and its pair's canonical encodings.
#[derive(Clone, Debug, PartialEq, TotalEq)]
pub struct ActionPair {
    /// The action descriptor.
    pub descriptor: [u8; 64],
    /// The tachygrams, in their stored order.
    pub pair: [[u8; 32]; 2],
}

/// The byte fields for one pre-fee proof.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("ActionsProof(..)")]
pub struct ActionsProof {
    /// Covered descriptors and their pairs in descriptor order.
    pub pairs: Vec<ActionPair>,
    /// The proof's anchor.
    pub anchor: [u8; 32],
    /// The versioned, uncompressed Ragu proof.
    pub proof: Vec<u8>,
}

/// The inseparable byte fields produced when applying a fee.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("AutonomeParts(..)")]
pub struct AutonomeParts {
    /// The uncompressed stamp in its canonical encoding.
    pub stamp: Vec<u8>,
    /// Covered descriptors and their pairs in descriptor order.
    pub pairs: Vec<ActionPair>,
    /// The fee paid in zatoshis.
    pub fee: u64,
    /// The canonical change commitment.
    pub cm_change: [u8; 32],
}

/// A field of the byte mirror.
#[derive(Clone, Copy, Debug, Display)]
pub enum Field {
    /// The bundle proving anchor.
    Anchor,
    /// Lineage data at an action.
    #[display("lineage at action {_0}")]
    Lineage(usize),
    /// Spend validating key at an action.
    #[display("validating key at action {_0}")]
    Ak(usize),
    /// Nullifier key at an action.
    #[display("nullifier key at action {_0}")]
    Nk(usize),
    /// Action list.
    Actions,
    /// Memo.
    Memo,
    /// Bundle balance.
    ValueBalance,
    /// Binding signing key.
    Bsk,
    /// Action descriptor.
    #[display("descriptor at action {_0}")]
    Descriptor(usize),
    /// Action entropy.
    #[display("theta at action {_0}")]
    Theta(usize),
    /// Value commitment trapdoor.
    #[display("rcv at action {_0}")]
    Rcv(usize),
    /// Action signature.
    #[display("signature at action {_0}")]
    Signature(usize),
    /// Maximum fee commitment.
    MaxFee,
    /// A field in an action's note.
    #[display("note {_1} at action {_0}")]
    ActionNote(usize, NoteField),
    /// A field in the maximum fee note.
    #[display("maximum fee note {_0}")]
    MaxFeeNote(NoteField),
    /// The list of pre-fee proofs.
    ActionsProofs,
    /// A field belonging to a proof contribution.
    #[display("{_1} in {_0}")]
    Proof(ProofLocation, ProofField),
}

/// The proof contribution being read.
#[derive(Clone, Copy, Debug, Display)]
pub enum ProofLocation {
    /// An indexed pre-fee proof.
    #[display("actions proof {_0}")]
    ActionsProof(usize),
    /// The fee-applied proof.
    #[display("autonome parts")]
    AutonomeParts,
}

/// A field of a proof contribution.
#[derive(Clone, Copy, Debug, Display)]
pub enum ProofField {
    /// Proof anchor.
    Anchor,
    /// Uncompressed proof.
    Proof,
    /// Proof stamp.
    Stamp,
    /// Action descriptor in a pair.
    Descriptor,
    /// Set of action pairs.
    Pairs,
    /// An action tachygram.
    Tachygram,
    /// Fee paid.
    Fee,
    /// Fee change commitment.
    Change,
}

/// A decoded value violates an invariant.
#[derive(Clone, Copy, Debug, Display)]
pub enum ValueReason {
    /// Identity key or point.
    Identity,
    /// Value is out of range.
    Range,
    /// A section without actions must have zero balance.
    NonzeroActionlessBalance,
    /// An omitted effect could not be derived.
    CompactDerivation,
}

/// The cause of a mirror decoding failure.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum EncodingCause {
    /// The proof has an incorrect encoded length.
    #[display("expected {expected} proof bytes, got {actual}")]
    ProofLength {
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// A proof field is incomplete.
    #[display("truncated proof at byte {offset}: need {requested} bytes, have {available}")]
    ProofTruncated {
        /// Field offset.
        offset: usize,
        /// Required length.
        requested: usize,
        /// Available length.
        available: usize,
    },
    /// The proof decoder rejected a field.
    #[display("invalid proof at byte {offset}: {reason}")]
    ProofInvalid {
        /// Field offset.
        offset: usize,
        /// Diagnostic from the decoder.
        reason: &'static str,
    },
    /// A value has no Ragu proof encoding.
    #[display("unencodable proof")]
    ProofUnencodable,
    /// The proof decoder returned an unsupported diagnostic.
    #[display("proof decoder rejected the input")]
    ProofDecode,
    /// The verification key decoder rejected the key.
    #[display("{_0}")]
    VerificationKey(#[error(not(source))] reddsa::Error),
    /// The bytes are not canonical.
    #[display("noncanonical encoding")]
    Noncanonical,
    /// A field reader rejected the input.
    #[display("field reader rejected the input")]
    Read(io::Error),
    /// Bytes remain after decoding a complete field.
    #[display("trailing bytes")]
    TrailingBytes,
}

/// Invalid pre-fee proof coverage or pair ordering.
#[derive(Clone, Copy, Debug, Display)]
pub enum CoverageReason {
    /// An empty action subset.
    Empty,
    /// An unknown descriptor.
    Foreign,
    /// Action subsets intersect.
    Overlap,
}

/// A malformed or insufficient byte mirror.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Field decoding failed.
    #[display("invalid encoding for {_0}")]
    InvalidEncoding(#[error(not(source))] Field, #[error(source)] EncodingCause),
    /// A field is required to derive an omitted effect.
    #[display("missing {_0} for compact effect")]
    MissingForEffect(#[error(not(source))] MissingField),
    /// A value violates a field invariant.
    #[display("invalid {_0}: {_1}")]
    InvalidValue(
        #[error(not(source))] Field,
        #[error(not(source))] ValueReason,
    ),
    /// Section exceeds a size bound.
    #[display("limit exceeded for {_0}")]
    Limit(#[error(not(source))] Field),
    /// Descriptors are not strictly ascending.
    #[display("descriptors are not strictly ascending in {_0}")]
    DescriptorOrder(#[error(not(source))] DescriptorOrderLocation),
    /// Supplied spend authority and delegated key disagree.
    #[display("spend keys disagree at action {_0}")]
    KeyMismatch(#[error(not(source))] usize),
    /// Proof coverage is invalid.
    #[display("invalid coverage in actions proof {_0}: {_1}")]
    InvalidCoverage(
        #[error(not(source))] usize,
        #[error(not(source))] CoverageReason,
    ),
    /// A tachygram repeats within a proof contribution.
    #[display("duplicate tachygram in {_0}")]
    DuplicateTachygram(#[error(not(source))] ProofLocation),
}

/// A list whose descriptors must be strictly ascending.
#[derive(Clone, Copy, Debug, Display)]
pub enum DescriptorOrderLocation {
    /// The section's action list.
    #[display("actions")]
    Actions,
    /// The pairs in a proof contribution.
    #[display("pairs in {_0}")]
    Pairs(ProofLocation),
}

impl ParseError {
    const fn noncanonical(field: Field) -> Self {
        Self::InvalidEncoding(field, EncodingCause::Noncanonical)
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "mirror conversion is separate from section construction"
)]
impl pczt::Bundle {
    /// Parse the mirror without verifying its signatures or proofs.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid encoding or coverage, or an omitted
    /// effect without the opening needed to derive it.
    #[expect(
        clippy::too_many_lines,
        reason = "validate section fields and proof coverage together"
    )]
    pub fn parse(mirror: Bundle) -> Result<Self, ParseError> {
        if mirror.actions.len() > (ProductionRank::num_coeffs() - 2).div_euclid(2) {
            return Err(ParseError::Limit(Field::Actions));
        }
        CompactSize::from(
            u64::try_from(mirror.memo.len()).map_err(|_err| ParseError::Limit(Field::Memo))?,
        )
        .enforce_valid()
        .map_err(|_err| ParseError::Limit(Field::Memo))?;
        let actions = mirror
            .actions
            .into_iter()
            .enumerate()
            .map(|(index, action)| action.parse(index))
            .collect::<Result<Vec<_>, _>>()?;
        if actions
            .iter()
            .map(|action| action.descriptor)
            .zip(actions.iter().skip(1).map(|action| action.descriptor))
            .any(|(left, right)| left >= right)
        {
            return Err(ParseError::DescriptorOrder(
                DescriptorOrderLocation::Actions,
            ));
        }
        let max_fee = mirror.max_fee.parse()?;
        let balance =
            if let Some(balance) = mirror.value_balance {
                i128::from(balance)
            } else {
                let fee = max_fee.note.value.ok_or(ParseError::MissingForEffect(
                    MissingField::MaxFee(NoteField::Value),
                ))?;
                let mut sum = -i128::from(fee);
                for (index, action) in actions.iter().enumerate() {
                    let amount =
                        i128::from(action.note.value.ok_or(ParseError::MissingForEffect(
                            MissingField::Action(index, OpeningField::Note(NoteField::Value)),
                        ))?);
                    sum += match *action.witness.as_ref().ok_or(ParseError::MissingForEffect(
                        MissingField::Action(index, OpeningField::Witness),
                    ))? {
                        pczt::ActionWitness::Spend(_) => amount,
                        pczt::ActionWitness::Output(_) => -amount,
                    };
                }
                sum
            };
        let value_balance = value::Balance::try_from(balance)
            .map_err(|_err| ParseError::InvalidValue(Field::ValueBalance, ValueReason::Range))?;
        if actions.is_empty() && value_balance != value::Balance::ZERO {
            return Err(ParseError::InvalidValue(
                Field::ValueBalance,
                ValueReason::NonzeroActionlessBalance,
            ));
        }
        let descriptors: BTreeSet<_> = actions.iter().map(|action| action.descriptor).collect();
        let mut covered = BTreeSet::new();
        let mut actions_proofs = Vec::new();
        if mirror.actions_proofs.len() > actions.len() {
            return Err(ParseError::Limit(Field::ActionsProofs));
        }
        for (index, encoded) in mirror.actions_proofs.into_iter().enumerate() {
            let proof = encoded.parse(index)?;
            if proof.pairs.is_empty() {
                return Err(ParseError::InvalidCoverage(index, CoverageReason::Empty));
            }
            for descriptor in proof.pairs.keys() {
                if !descriptors.contains(descriptor) {
                    return Err(ParseError::InvalidCoverage(index, CoverageReason::Foreign));
                }
                if !covered.insert(*descriptor) {
                    return Err(ParseError::InvalidCoverage(index, CoverageReason::Overlap));
                }
            }
            actions_proofs.push(proof);
        }
        actions_proofs
            .sort_by(|left, right| left.pairs.keys().next().cmp(&right.pairs.keys().next()));
        Ok(Self {
            actions,
            value_balance,
            max_fee,
            memo: mirror.memo,
            anchor: mirror
                .anchor
                .map(|bytes| parse_anchor(bytes, Field::Anchor))
                .transpose()?,
            actions_proofs,
            autonome_parts: mirror
                .autonome_parts
                .map(AutonomeParts::parse)
                .transpose()?,
            bsk: mirror
                .bsk
                .map(|bytes| {
                    Fq::from_bytes(bytes)
                        .map(|scalar| {
                            private::BindingSigningKey::from([value::ValueTrapdoor(scalar)])
                        })
                        .ok_or_else(|| ParseError::noncanonical(Field::Bsk))
                })
                .transpose()?,
            proprietary: mirror.proprietary,
        })
    }

    /// Project the section into mirror fields. The container can redact
    /// fields individually or omit effects it expects parsing to derive.
    ///
    /// # Panics
    ///
    /// Panics if an in-memory proof has no encoding.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "fixed-width fields and in-memory proofs are encodable"
    )]
    pub fn to_mirror(&self) -> Bundle {
        Bundle {
            actions: self
                .actions
                .iter()
                .map(Action::serialize)
                .collect::<Result<_, _>>()
                .expect("action fields are encodable"),
            value_balance: Some(self.value_balance.into()),
            max_fee: MaxFee {
                cv_feemax: Some(self.max_fee.cv_feemax.into()),
                note: NoteOpening::from_opening(self.max_fee.note),
                zip32_derivation: self.max_fee.zip32_derivation.clone(),
                proprietary: self.max_fee.proprietary.clone(),
            },
            memo: self.memo.clone(),
            anchor: self
                .anchor
                .map(encode_anchor)
                .transpose()
                .expect("anchor is fixed width"),
            actions_proofs: self
                .actions_proofs
                .iter()
                .map(ActionsProof::serialize)
                .collect::<Result<_, _>>()
                .expect("actions proofs are encodable"),
            autonome_parts: self
                .autonome_parts
                .as_ref()
                .map(AutonomeParts::serialize)
                .transpose()
                .expect("stamp proof is encodable"),
            bsk: self.bsk.map(private::BindingSigningKey::to_bytes),
            proprietary: self.proprietary.clone(),
        }
    }
}

impl Action {
    fn parse(self, index: usize) -> Result<pczt::Action, ParseError> {
        let supplied = self
            .descriptor
            .map(|bytes| {
                action::Descriptor::read(bytes.as_slice()).map_err(|cause| {
                    ParseError::InvalidEncoding(
                        Field::Descriptor(index),
                        EncodingCause::Read(cause),
                    )
                })
            })
            .transpose()?;
        let note = self.note.parse(|field| Field::ActionNote(index, field))?;
        let theta = self
            .theta
            .map(|bytes| {
                ActionEntropy::from_bytes(bytes)
                    .ok_or_else(|| ParseError::noncanonical(Field::Theta(index)))
            })
            .transpose()?;
        let rcv = self
            .rcv
            .map(|bytes| {
                Fq::from_bytes(bytes)
                    .map(value::ValueTrapdoor)
                    .ok_or_else(|| ParseError::noncanonical(Field::Rcv(index)))
            })
            .transpose()?;
        let witness = self
            .witness
            .map(|witness| witness.parse(index))
            .transpose()?;
        let sig = self
            .sig
            .map(|bytes| {
                action::Signature::read(bytes.as_slice()).map_err(|cause| {
                    ParseError::InvalidEncoding(Field::Signature(index), EncodingCause::Read(cause))
                })
            })
            .transpose()?;
        let descriptor = if let Some(desc) = supplied {
            desc
        } else {
            let desc = pczt::Action::derive_from_opening(&note, theta, rcv, witness.as_ref())
                .map_err(|err| match err {
                    DescriptorError::Missing(field) => {
                        ParseError::MissingForEffect(MissingField::Action(index, field))
                    },
                    DescriptorError::ZeroRcm => ParseError::InvalidValue(
                        Field::Descriptor(index),
                        ValueReason::CompactDerivation,
                    ),
                })?;
            if EpAffine::from(desc.cv).is_identity() || EpAffine::from(desc.rk).is_identity() {
                return Err(ParseError::InvalidValue(
                    Field::Descriptor(index),
                    ValueReason::Identity,
                ));
            }
            desc
        };
        Ok(pczt::Action {
            descriptor,
            sig,
            note,
            theta,
            rcv,
            witness,
            proprietary: self.proprietary,
        })
    }

    fn serialize(action: &pczt::Action) -> io::Result<Self> {
        Ok(Self {
            descriptor: Some(encode_descriptor(action.descriptor)?),
            sig: action.sig.map(|sig| sig.0.into()),
            note: NoteOpening::from_opening(action.note),
            theta: action.theta.as_ref().map(ActionEntropy::to_bytes),
            rcv: action.rcv.map(|rcv| Fq::from(rcv).to_bytes()),
            witness: action
                .witness
                .as_ref()
                .map(ActionWitness::serialize)
                .transpose()?,
            proprietary: action.proprietary.clone(),
        })
    }
}

impl MaxFee {
    fn parse(self) -> Result<pczt::MaxFee, ParseError> {
        let note = self.note.parse(Field::MaxFeeNote)?;
        let cv_feemax = match self.cv_feemax {
            Some(bytes) => EpAffine::from_bytes(bytes)
                .map(value::Commitment::from)
                .ok_or_else(|| ParseError::noncanonical(Field::MaxFee))?,
            None => note
                .complete()
                .map_err(|field| ParseError::MissingForEffect(MissingField::MaxFee(field)))?
                .cv_feemax(),
        };
        if EpAffine::from(cv_feemax).is_identity() {
            return Err(ParseError::InvalidValue(
                Field::MaxFee,
                ValueReason::Identity,
            ));
        }
        Ok(pczt::MaxFee {
            cv_feemax,
            note,
            zip32_derivation: self.zip32_derivation,
            proprietary: self.proprietary,
        })
    }
}

impl NoteOpening {
    fn from_opening(note: pczt::NoteOpening) -> Self {
        Self {
            pk: note.pk.map(|pk| Fp::from(pk).to_bytes()),
            value: note.value.map(u64::from),
            psi: note.psi.map(|psi| Fp::from(psi).to_bytes()),
            rcm: note.rcm.map(|rcm| Fp::from(rcm).to_bytes()),
        }
    }

    fn parse(self, field: impl Fn(NoteField) -> Field) -> Result<pczt::NoteOpening, ParseError> {
        Ok(pczt::NoteOpening {
            pk: self
                .pk
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Pk)))
                })
                .transpose()?,
            value: self
                .value
                .map(|amount| {
                    value::Positive::try_from(amount).map_err(|_err| {
                        ParseError::InvalidValue(field(NoteField::Value), ValueReason::Range)
                    })
                })
                .transpose()?,
            psi: self
                .psi
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Psi)))
                })
                .transpose()?,
            rcm: self
                .rcm
                .map(|bytes| {
                    Fp::from_bytes(bytes)
                        .map(Into::into)
                        .ok_or_else(|| ParseError::noncanonical(field(NoteField::Rcm)))
                })
                .transpose()?,
        })
    }
}

fn parse_ak(bytes: [u8; 32], index: usize) -> Result<SpendValidatingKey, ParseError> {
    reddsa::VerificationKey::try_from(bytes)
        .map(SpendValidatingKey)
        .map_err(|cause| {
            ParseError::InvalidEncoding(Field::Ak(index), EncodingCause::VerificationKey(cause))
        })
}

impl ActionWitness {
    fn parse(self, index: usize) -> Result<pczt::ActionWitness, ParseError> {
        Ok(match self {
            Self::Spend(spend) => {
                let ak = spend.ak.map(|bytes| parse_ak(bytes, index)).transpose()?;
                let pak = spend
                    .pak
                    .map(|[delegated, nk]| -> Result<_, ParseError> {
                        Ok(Box::new(ProofAuthorizingKey {
                            ak: parse_ak(delegated, index)?,
                            nk: NullifierKey::from_field(
                                Fp::from_bytes(nk)
                                    .ok_or_else(|| ParseError::noncanonical(Field::Nk(index)))?,
                            ),
                        }))
                    })
                    .transpose()?;
                pczt::SpendWitness::validate_keys(ak, pak.as_deref().copied()).map_err(|err| {
                    match err {
                        SpendKeyError::Invalid => {
                            ParseError::InvalidValue(Field::Ak(index), ValueReason::Identity)
                        },
                        SpendKeyError::Mismatch => ParseError::KeyMismatch(index),
                    }
                })?;
                pczt::ActionWitness::Spend(pczt::SpendWitness {
                    ak,
                    pak,
                    lineage: spend
                        .lineage
                        .map(|lineage| lineage.parse(index))
                        .transpose()?,
                    zip32_derivation: spend.zip32_derivation,
                })
            },
            Self::Output(output) => pczt::ActionWitness::Output(pczt::OutputWitness {
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
            }),
        })
    }

    #[expect(clippy::ref_patterns, reason = "borrow witness fields")]
    fn serialize(witness: &pczt::ActionWitness) -> io::Result<Self> {
        Ok(match *witness {
            pczt::ActionWitness::Spend(ref spend) => Self::Spend(SpendWitness {
                ak: spend.ak.map(|ak| ak.0.into()),
                pak: spend
                    .pak()
                    .map(|pak| [pak.ak.0.into(), Fp::from(pak.nk).to_bytes()]),
                lineage: spend
                    .lineage
                    .as_ref()
                    .map(SpendLineage::serialize)
                    .transpose()?,
                zip32_derivation: spend.zip32_derivation.clone(),
            }),
            pczt::ActionWitness::Output(ref output) => Self::Output(OutputWitness {
                zip32_derivation: output.zip32_derivation.clone(),
                user_address: output.user_address.clone(),
            }),
        })
    }
}

fn encode_descriptor(descriptor: action::Descriptor) -> io::Result<[u8; 64]> {
    let mut bytes = [0; 64];
    descriptor.write(bytes.as_mut_slice())?;
    Ok(bytes)
}

fn encode_anchor(anchor: Anchor) -> io::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    anchor.write(bytes.as_mut_slice())?;
    Ok(bytes)
}

fn parse_anchor(bytes: [u8; 32], field: Field) -> Result<Anchor, ParseError> {
    Anchor::read(bytes.as_slice())
        .map_err(|cause| ParseError::InvalidEncoding(field, EncodingCause::Read(cause)))
}

#[expect(
    clippy::expect_used,
    reason = "Ragu-produced proofs have a canonical encoding"
)]
fn encode_proof(proof: &stamp::Uncompressed) -> Vec<u8> {
    proof.to_bytes().expect("Ragu-produced proof is encodable")
}

fn parse_proof(bytes: &[u8], field: Field) -> Result<stamp::Uncompressed, ParseError> {
    let expected = stamp::Uncompressed::encoded_len::<{ stamp::proof::HEADER_SIZE }>();
    if bytes.len() != expected {
        return Err(ParseError::InvalidEncoding(
            field,
            EncodingCause::ProofLength {
                expected,
                actual: bytes.len(),
            },
        ));
    }
    stamp::Uncompressed::from_bytes(bytes).map_err(|cause| {
        use ragu::pcd::wire::Error as WireError;
        let diagnostic = match cause {
            WireError::Length {
                expected: wire_len,
                actual,
            } => EncodingCause::ProofLength {
                expected: wire_len,
                actual,
            },
            WireError::Truncated {
                offset,
                requested,
                bytes: remainder,
            } => EncodingCause::ProofTruncated {
                offset,
                requested,
                available: remainder.len(),
            },
            WireError::Invalid { offset, reason, .. } => {
                EncodingCause::ProofInvalid { offset, reason }
            },
            WireError::Unencodable => EncodingCause::ProofUnencodable,
            _ => EncodingCause::ProofDecode,
        };
        ParseError::InvalidEncoding(field, diagnostic)
    })
}

impl SpendLineage {
    fn parse(self, index: usize) -> Result<pczt::SpendLineage, ParseError> {
        let field = Field::Lineage(index);
        let encoding = |cause| ParseError::InvalidEncoding(field, EncodingCause::Read(cause));
        let mut secret_bytes = self.secret.as_slice();
        let cm = serialization::read_fp(&mut secret_bytes).map_err(encoding)?;
        let pk = serialization::read_fp(&mut secret_bytes).map_err(encoding)?;
        let (value_bytes, mut note_tail) = secret_bytes
            .split_first_chunk::<8>()
            .ok_or_else(|| ParseError::noncanonical(field))?;
        let value = value::Positive::try_from(u64::from_le_bytes(*value_bytes))
            .map_err(|_err| ParseError::InvalidValue(field, ValueReason::Range))?;
        let psi = serialization::read_fp(&mut note_tail).map_err(encoding)?;
        let rcm = serialization::read_fp(&mut note_tail).map_err(encoding)?;
        let mk = NoteMasterKey(serialization::read_fp(&mut note_tail).map_err(encoding)?);
        let note = Note {
            pk: pk.into(),
            value,
            psi: psi.into(),
            rcm: rcm.into(),
        };
        let secret =
            parse_proof(note_tail, field)?.carry::<delegation::NoteSecret>((cm.into(), note, mk));

        let mut spendable_bytes = self.spendable.as_slice();
        let spendable_cm = serialization::read_fp(&mut spendable_bytes).map_err(encoding)?;
        let (epoch_bytes, mut spendable_tail) = spendable_bytes
            .split_first_chunk::<4>()
            .ok_or_else(|| ParseError::noncanonical(field))?;
        let epoch = u32::from_le_bytes(*epoch_bytes);
        if epoch > EPOCH_MAX {
            return Err(ParseError::InvalidValue(field, ValueReason::Range));
        }
        let anchor = Anchor::read(&mut spendable_tail).map_err(encoding)?;
        let spendable = parse_proof(spendable_tail, field)?.carry::<spendable::NoteSpendable>((
            spendable_cm.into(),
            EpochIndex::new(epoch),
            anchor,
        ));

        let spans = self
            .spans
            .iter()
            .map(|span| {
                let mut bytes = span.as_slice();
                let start = Anchor::read(&mut bytes).map_err(encoding)?;
                let end = Anchor::read(&mut bytes).map_err(encoding)?;
                Ok(parse_proof(bytes, field)?.carry::<pool::AnchorSpan>((start, end)))
            })
            .collect::<Result<_, ParseError>>()?;
        Ok(pczt::SpendLineage::new(secret, spendable, spans))
    }

    fn serialize(lineage: &pczt::SpendLineage) -> io::Result<Self> {
        let (cm, note, mk) = *lineage.secret.data();
        let mut secret = Vec::new();
        secret.extend_from_slice(&Fp::from(cm).to_bytes());
        secret.extend_from_slice(&Fp::from(note.pk).to_bytes());
        secret.extend_from_slice(&u64::from(note.value).to_le_bytes());
        secret.extend_from_slice(&Fp::from(note.psi).to_bytes());
        secret.extend_from_slice(&Fp::from(note.rcm).to_bytes());
        secret.extend_from_slice(&mk.0.to_bytes());
        secret.extend(encode_proof(lineage.secret.proof()));
        let (spendable_cm, epoch, anchor) = *lineage.spendable.data();
        let mut spendable = Vec::new();
        spendable.extend_from_slice(&Fp::from(spendable_cm).to_bytes());
        spendable.extend_from_slice(&u32::from(epoch).to_le_bytes());
        anchor.write(&mut spendable)?;
        spendable.extend(encode_proof(lineage.spendable.proof()));
        let spans = lineage
            .spans
            .iter()
            .map(|span| {
                let (start, end) = *span.data();
                let mut bytes = Vec::new();
                start.write(&mut bytes)?;
                end.write(&mut bytes)?;
                bytes.extend(encode_proof(span.proof()));
                Ok(bytes)
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            secret,
            spendable,
            spans,
        })
    }
}

impl ActionPair {
    fn parse_all(
        pairs: Vec<Self>,
        location: ProofLocation,
    ) -> Result<BTreeMap<action::Descriptor, (Tachygram, Tachygram)>, ParseError> {
        let field = |field| Field::Proof(location, field);
        if pairs.len() > (ProductionRank::num_coeffs() - 2).div_euclid(2) {
            return Err(ParseError::Limit(field(ProofField::Pairs)));
        }
        let mut result = BTreeMap::new();
        for Self {
            descriptor,
            pair: [left_bytes, right_bytes],
        } in pairs
        {
            let desc = action::Descriptor::read(descriptor.as_slice()).map_err(|cause| {
                ParseError::InvalidEncoding(
                    field(ProofField::Descriptor),
                    EncodingCause::Read(cause),
                )
            })?;
            let left = Tachygram::read(left_bytes.as_slice()).map_err(|cause| {
                ParseError::InvalidEncoding(
                    field(ProofField::Tachygram),
                    EncodingCause::Read(cause),
                )
            })?;
            let right = Tachygram::read(right_bytes.as_slice()).map_err(|cause| {
                ParseError::InvalidEncoding(
                    field(ProofField::Tachygram),
                    EncodingCause::Read(cause),
                )
            })?;
            if result
                .last_key_value()
                .is_some_and(|(prev, _)| *prev >= desc)
            {
                return Err(ParseError::DescriptorOrder(DescriptorOrderLocation::Pairs(
                    location,
                )));
            }
            result.insert(desc, (left, right));
        }
        Ok(result)
    }

    fn serialize_all(
        pairs: &BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
    ) -> io::Result<Vec<Self>> {
        pairs
            .iter()
            .map(|(&descriptor, &(left, right))| {
                Ok(Self {
                    descriptor: encode_descriptor(descriptor)?,
                    pair: [Fp::from(left).to_bytes(), Fp::from(right).to_bytes()],
                })
            })
            .collect()
    }
}

impl ActionsProof {
    fn parse(self, index: usize) -> Result<stamp::ActionsProof, ParseError> {
        let location = ProofLocation::ActionsProof(index);
        let pairs = ActionPair::parse_all(self.pairs, location)?;
        if !Tachygram::all_distinct(pairs.values().copied().flat_map(<[Tachygram; 2]>::from)) {
            return Err(ParseError::DuplicateTachygram(location));
        }
        Ok(stamp::ActionsProof {
            pairs,
            anchor: parse_anchor(self.anchor, Field::Proof(location, ProofField::Anchor))?,
            proof: Box::new(parse_proof(
                &self.proof,
                Field::Proof(location, ProofField::Proof),
            )?),
        })
    }

    fn serialize(proof: &stamp::ActionsProof) -> io::Result<Self> {
        Ok(Self {
            pairs: ActionPair::serialize_all(&proof.pairs)?,
            anchor: encode_anchor(proof.anchor)?,
            proof: encode_proof(&proof.proof),
        })
    }
}

impl AutonomeParts {
    fn parse(self) -> Result<stamp::AutonomeParts, ParseError> {
        let location = ProofLocation::AutonomeParts;
        let field = |field| Field::Proof(location, field);
        let mut bytes = self.stamp.as_slice();
        let stamp = stamp::ProofStamp::read(&mut bytes).map_err(|cause| {
            ParseError::InvalidEncoding(field(ProofField::Stamp), EncodingCause::Read(cause))
        })?;
        if !bytes.is_empty() {
            return Err(ParseError::InvalidEncoding(
                field(ProofField::Stamp),
                EncodingCause::TrailingBytes,
            ));
        }
        let pairs = ActionPair::parse_all(self.pairs, location)?;
        let cm_change = Tachygram::read(self.cm_change.as_slice()).map_err(|cause| {
            ParseError::InvalidEncoding(field(ProofField::Change), EncodingCause::Read(cause))
        })?;
        if !Tachygram::all_distinct(
            pairs
                .values()
                .copied()
                .flat_map(<[Tachygram; 2]>::from)
                .chain([cm_change]),
        ) {
            return Err(ParseError::DuplicateTachygram(location));
        }
        Ok(stamp::AutonomeParts {
            stamp,
            pairs,
            fee: value::Positive::try_from(self.fee).map_err(|_err| {
                ParseError::InvalidValue(field(ProofField::Fee), ValueReason::Range)
            })?,
            cm_change,
        })
    }

    fn serialize(parts: &stamp::AutonomeParts) -> io::Result<Self> {
        let mut bytes = Vec::new();
        parts.stamp.write(&mut bytes)?;
        Ok(Self {
            stamp: bytes,
            pairs: ActionPair::serialize_all(&parts.pairs)?,
            fee: parts.fee.into(),
            cm_change: Fp::from(parts.cm_change).to_bytes(),
        })
    }
}
