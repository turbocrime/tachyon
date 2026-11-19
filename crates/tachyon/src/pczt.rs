//! The Tachyon section of a partially constructed transaction.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};

use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};
use ragu::{Pcd, ProductionRank, pasta::Pasta};
use udon::field::Field as _;

use crate::{
    Anchor, Note, action, bundle,
    entropy::ActionEntropy,
    keys::{PaymentKey, ProofAuthorizingKey, SpendValidatingKey, private},
    note, nullifier,
    pasta::Fp,
    primitives::{Effect, effect},
    stamp::{
        self,
        proof::{delegation, pool, spendable},
    },
    value,
};

/// A section with a fixed list of actions in commitment order.
#[derive(Clone, Debug)]
pub struct Bundle {
    actions: Vec<Action>,
    value_balance: value::Balance,
    max_fee: MaxFee,
    memo: Vec<u8>,
    anchor: Option<Anchor>,
    actions_proofs: Vec<stamp::ActionsProof>,
    autonome_parts: Option<stamp::AutonomeParts>,
    bsk: Option<private::BindingSigningKey>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// An action's immutable descriptor and its optional fields.
#[derive(Clone, Debug)]
pub struct Action {
    descriptor: action::Descriptor,
    sig: Option<action::Signature>,
    note: NoteOpening,
    theta: Option<ActionEntropy>,
    rcv: Option<value::Trapdoor>,
    witness: Option<ActionWitness>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// Independently redactable note fields.
#[derive(Clone, Copy, Debug)]
#[debug("NoteOpening(..)")]
pub struct NoteOpening {
    pk: Option<PaymentKey>,
    value: Option<value::Positive>,
    psi: Option<nullifier::Trapdoor>,
    rcm: Option<note::CommitmentTrapdoor>,
}

/// Information specific to one action kind.
#[derive(Clone, Debug)]
pub enum ActionWitness {
    /// A spend.
    Spend(SpendWitness),
    /// An output.
    Output(OutputWitness),
}

/// Spend authority, delegated proving data and signer metadata.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    ak: Option<SpendValidatingKey>,
    pak: Option<Box<ProofAuthorizingKey>>,
    lineage: Option<SpendLineage>,
    zip32_derivation: Option<Zip32Derivation>,
}

/// The predecessor proofs used by a spend.
#[derive(Clone, Debug)]
#[debug("SpendLineage(..)")]
pub struct SpendLineage {
    secret: Box<Pcd<Pasta, ProductionRank, delegation::NoteSecret>>,
    spendable: Box<Pcd<Pasta, ProductionRank, spendable::NoteSpendable>>,
    spans: Vec<Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
}

/// Hints for reviewing an output.
#[derive(Clone, Debug)]
pub struct OutputWitness {
    zip32_derivation: Option<Zip32Derivation>,
    #[debug(skip)]
    user_address: Option<String>,
}

/// Hint for locating a key; not part of the effects.
#[derive(Clone, Debug, PartialEq, TotalEq)]
#[debug("Zip32Derivation(..)")]
pub struct Zip32Derivation {
    seed_fingerprint: [u8; 32],
    derivation_path: Vec<u32>,
}

/// The committed maximum fee and its optional opening and metadata.
#[derive(Clone, Debug)]
pub struct MaxFee {
    cv_feemax: value::Commitment,
    note: NoteOpening,
    zip32_derivation: Option<Zip32Derivation>,
    #[debug(skip)]
    proprietary: BTreeMap<String, Vec<u8>>,
}

/// An opening is incomplete or fails to reproduce the effects.
#[derive(Clone, Copy, Debug, Display, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A needed field is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] OpeningField),
    /// The opening cannot produce the stored effects.
    #[display("action descriptor mismatch")]
    DescriptorMismatch,
    /// The note commitment trapdoor is zero.
    #[display("zero note commitment trapdoor")]
    ZeroRcm,
}

enum DescriptorError {
    Missing(OpeningField),
    ZeroRcm,
}

/// An input to a PCZT opening.
#[derive(Clone, Copy, Debug, Display)]
pub enum OpeningField {
    /// Action kind.
    Witness,
    /// Spend validating key.
    Ak,
    /// An opening field of the note.
    #[display("note {_0}")]
    Note(NoteField),
    /// Action entropy.
    Theta,
    /// Value commitment trapdoor.
    Rcv,
}

/// A field of a note opening.
#[derive(Clone, Copy, Debug, Display)]
pub enum NoteField {
    /// Payment key.
    Pk,
    /// Note value.
    Value,
    /// Nullifier trapdoor.
    Psi,
    /// Note commitment trapdoor.
    Rcm,
}

/// A missing input and its position in the section.
#[derive(Clone, Copy, Debug, Display)]
#[expect(
    variant_size_differences,
    reason = "only indexed action fields carry a position"
)]
pub enum MissingField {
    /// A field of the indexed action.
    #[display("action {_0} {_1}")]
    Action(usize, OpeningField),
    /// A field of the max fee opening.
    #[display("max fee {_0}")]
    MaxFee(NoteField),
}

/// An effect that does not match the derived plan.
#[derive(Clone, Copy, Debug, Display)]
pub enum ReviewEffect {
    /// Bundle balance.
    ValueBalance,
    /// Maximum fee commitment.
    MaxFee,
    /// Descriptor of the indexed action.
    Action(usize),
}

/// Failure to reconstruct the reviewed plan.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ReviewError {
    /// An opening is incomplete.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] MissingField),
    /// Plan construction failed.
    #[display("invalid reviewed plan")]
    Plan(bundle::PlanError),
    /// A reconstructed effect differs from the section.
    #[display("effect mismatch: {_0}")]
    EffectsMismatch(#[error(not(source))] ReviewEffect),
}

impl Bundle {
    /// Open the section from a complete plan, without role contributions.
    #[must_use]
    pub fn from_plan(plan: &bundle::Plan) -> Self {
        let effects = plan.effects();
        let mut actions: Vec<_> = plan
            .spends()
            .iter()
            .map(|&(descriptor, opening)| {
                Action::from_plan(
                    descriptor,
                    opening,
                    ActionWitness::Spend(SpendWitness {
                        ak: Some(opening.authority),
                        pak: None,
                        lineage: None,
                        zip32_derivation: None,
                    }),
                )
            })
            .chain(plan.outputs().iter().map(|&(descriptor, opening)| {
                Action::from_plan(
                    descriptor,
                    opening,
                    ActionWitness::Output(OutputWitness {
                        zip32_derivation: None,
                        user_address: None,
                    }),
                )
            }))
            .collect();
        actions.sort_unstable_by_key(|action| action.descriptor);
        Self {
            actions,
            value_balance: effects.value_balance,
            max_fee: MaxFee {
                cv_feemax: effects.cv_feemax,
                note: NoteOpening::from_note(plan.max_fee_note()),
                zip32_derivation: None,
                proprietary: BTreeMap::new(),
            },
            memo: effects.memo.clone(),
            anchor: None,
            actions_proofs: Vec::new(),
            autonome_parts: None,
            bsk: None,
            proprietary: BTreeMap::new(),
        }
    }

    /// The stored effects, which need not have openings.
    #[must_use]
    pub fn effects(&self) -> bundle::Effects {
        bundle::Effects {
            value_balance: self.value_balance,
            actions: self
                .actions
                .iter()
                .map(|action| action.descriptor)
                .collect(),
            cv_feemax: self.max_fee.cv_feemax,
            memo: self.memo.clone(),
        }
    }

    /// Derive a complete plan and compare its effects with the section's.
    ///
    /// # Errors
    ///
    /// Returns an error if an opening is missing or inconsistent.
    #[expect(clippy::ref_patterns, reason = "borrow the spend opening")]
    pub fn plan(&self) -> Result<bundle::Plan, ReviewError> {
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        let mut spend_indices = Vec::new();
        let mut output_indices = Vec::new();
        for (index, action) in self.actions.iter().enumerate() {
            let missing = |field| ReviewError::Missing(MissingField::Action(index, field));
            match *action
                .witness
                .as_ref()
                .ok_or_else(|| missing(OpeningField::Witness))?
            {
                ActionWitness::Spend(ref spend) => {
                    spends.push(
                        action
                            .opening::<effect::Spend>(
                                spend.ak.ok_or_else(|| missing(OpeningField::Ak))?,
                            )
                            .map_err(missing)?,
                    );
                    spend_indices.push(index);
                },
                ActionWitness::Output(_) => {
                    outputs.push(action.opening::<effect::Output>(()).map_err(missing)?);
                    output_indices.push(index);
                },
            }
        }
        let plan = bundle::Plan::new(
            spends,
            outputs,
            self.max_fee
                .note
                .complete()
                .map_err(|field| ReviewError::Missing(MissingField::MaxFee(field)))?,
            self.memo.clone(),
        )
        .map_err(ReviewError::Plan)?;
        if self.value_balance != plan.effects().value_balance {
            return Err(ReviewError::EffectsMismatch(ReviewEffect::ValueBalance));
        }
        if self.max_fee.cv_feemax != plan.effects().cv_feemax {
            return Err(ReviewError::EffectsMismatch(ReviewEffect::MaxFee));
        }
        // Plan retains input order within each action kind for its proving inputs.
        let checked = spend_indices
            .into_iter()
            .zip(plan.spends().iter().map(|entry| entry.0))
            .chain(
                output_indices
                    .into_iter()
                    .zip(plan.outputs().iter().map(|entry| entry.0)),
            );
        for (index, descriptor) in checked {
            if self.actions.get(index).map(Action::descriptor) != Some(descriptor) {
                return Err(ReviewError::EffectsMismatch(ReviewEffect::Action(index)));
            }
        }
        Ok(plan)
    }

    /// The actions in commitment order.
    #[must_use]
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The net value balance.
    #[must_use]
    pub const fn value_balance(&self) -> value::Balance {
        self.value_balance
    }

    /// The bundle memo.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }

    /// The maximum fee.
    #[must_use]
    pub const fn max_fee(&self) -> &MaxFee {
        &self.max_fee
    }

    /// The optional proving target.
    #[must_use]
    pub const fn anchor(&self) -> Option<Anchor> {
        self.anchor
    }

    /// The disjoint pre-fee proofs.
    #[must_use]
    pub fn actions_proofs(&self) -> &[stamp::ActionsProof] {
        &self.actions_proofs
    }

    /// The fee-applied proof and its associated data.
    #[must_use]
    pub const fn autonome_parts(&self) -> Option<&stamp::AutonomeParts> {
        self.autonome_parts.as_ref()
    }

    /// The key computed by the IO Finalizer.
    #[must_use]
    pub const fn bsk(&self) -> Option<&private::BindingSigningKey> {
        self.bsk.as_ref()
    }

    /// Bundle metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl Action {
    const fn from_plan<E: Effect>(
        descriptor: action::Descriptor,
        plan: action::Plan<E>,
        witness: ActionWitness,
    ) -> Self {
        Self {
            descriptor,
            sig: None,
            note: NoteOpening::from_note(plan.note),
            theta: Some(plan.theta),
            rcv: Some(plan.rcv),
            witness: Some(witness),
            proprietary: BTreeMap::new(),
        }
    }

    fn opening<E: Effect>(&self, authority: E::Authority) -> Result<action::Plan<E>, OpeningField> {
        Self::opening_from(&self.note, self.theta, self.rcv, authority)
    }

    fn opening_from<E: Effect>(
        note: &NoteOpening,
        theta: Option<ActionEntropy>,
        rcv: Option<value::Trapdoor>,
        authority: E::Authority,
    ) -> Result<action::Plan<E>, OpeningField> {
        Ok(action::Plan {
            note: note.complete().map_err(OpeningField::Note)?,
            theta: theta.ok_or(OpeningField::Theta)?,
            rcv: rcv.ok_or(OpeningField::Rcv)?,
            authority,
        })
    }

    /// Compare the derived descriptor with the stored descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or inconsistent opening.
    pub fn verify_opening(&self) -> Result<(), VerifyError> {
        if Self::derive_from_opening(&self.note, self.theta, self.rcv, self.witness.as_ref())
            .map_err(|error| match error {
                DescriptorError::Missing(field) => VerifyError::Missing(field),
                DescriptorError::ZeroRcm => VerifyError::ZeroRcm,
            })?
            != self.descriptor
        {
            return Err(VerifyError::DescriptorMismatch);
        }
        Ok(())
    }

    #[expect(clippy::ref_patterns, reason = "borrow the spend opening")]
    fn derive_from_opening(
        note: &NoteOpening,
        theta: Option<ActionEntropy>,
        rcv: Option<value::Trapdoor>,
        witness: Option<&ActionWitness>,
    ) -> Result<action::Descriptor, DescriptorError> {
        Ok(
            match *witness.ok_or(DescriptorError::Missing(OpeningField::Witness))? {
                ActionWitness::Spend(ref spend) => Self::checked_descriptor(
                    Self::opening_from::<effect::Spend>(
                        note,
                        theta,
                        rcv,
                        spend.ak.ok_or(DescriptorError::Missing(OpeningField::Ak))?,
                    )
                    .map_err(DescriptorError::Missing)?,
                )
                .ok_or(DescriptorError::ZeroRcm)?,
                ActionWitness::Output(_) => Self::checked_descriptor(
                    Self::opening_from::<effect::Output>(note, theta, rcv, ())
                        .map_err(DescriptorError::Missing)?,
                )
                .ok_or(DescriptorError::ZeroRcm)?,
            },
        )
    }

    fn checked_descriptor<E: Effect>(plan: action::Plan<E>) -> Option<action::Descriptor> {
        (Fp::from(plan.note.rcm) != Fp::ZERO).then(|| plan.descriptor())
    }

    /// The action's descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> action::Descriptor {
        self.descriptor
    }

    /// Its authorization signature, if present.
    #[must_use]
    pub const fn sig(&self) -> Option<action::Signature> {
        self.sig
    }

    /// The note's opening fields.
    #[must_use]
    pub const fn note(&self) -> &NoteOpening {
        &self.note
    }

    /// Its entropy.
    #[must_use]
    pub const fn theta(&self) -> Option<ActionEntropy> {
        self.theta
    }

    /// Its value commitment trapdoor.
    #[must_use]
    pub const fn rcv(&self) -> Option<value::Trapdoor> {
        self.rcv
    }

    /// Action-kind-specific data.
    #[must_use]
    pub const fn witness(&self) -> Option<&ActionWitness> {
        self.witness.as_ref()
    }

    /// Action metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl NoteOpening {
    const fn from_note(note: Note) -> Self {
        Self {
            pk: Some(note.pk),
            value: Some(note.value),
            psi: Some(note.psi),
            rcm: Some(note.rcm),
        }
    }

    fn complete(&self) -> Result<Note, NoteField> {
        Ok(Note {
            pk: self.pk.ok_or(NoteField::Pk)?,
            value: self.value.ok_or(NoteField::Value)?,
            psi: self.psi.ok_or(NoteField::Psi)?,
            rcm: self.rcm.ok_or(NoteField::Rcm)?,
        })
    }

    /// The payment key.
    #[must_use]
    pub const fn pk(&self) -> Option<PaymentKey> {
        self.pk
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> Option<value::Positive> {
        self.value
    }

    /// The nullifier trapdoor.
    #[must_use]
    pub const fn psi(&self) -> Option<nullifier::Trapdoor> {
        self.psi
    }

    /// The note commitment trapdoor.
    #[must_use]
    pub const fn rcm(&self) -> Option<note::CommitmentTrapdoor> {
        self.rcm
    }
}

impl MaxFee {
    /// The commitment to the maximum fee.
    #[must_use]
    pub const fn cv_feemax(&self) -> value::Commitment {
        self.cv_feemax
    }

    /// The max fee note's opening fields.
    #[must_use]
    pub const fn note(&self) -> &NoteOpening {
        &self.note
    }

    /// The change recipient's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }

    /// Max fee metadata.
    #[must_use]
    pub const fn proprietary(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.proprietary
    }
}

impl SpendWitness {
    /// The spend's owner.
    #[must_use]
    pub const fn ak(&self) -> Option<SpendValidatingKey> {
        self.ak
    }

    /// The proving capability.
    #[must_use]
    pub fn pak(&self) -> Option<ProofAuthorizingKey> {
        self.pak.as_deref().copied()
    }

    /// The predecessor proofs.
    #[must_use]
    pub const fn lineage(&self) -> Option<&SpendLineage> {
        self.lineage.as_ref()
    }

    /// The owner's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }
}

impl SpendLineage {
    /// Supply the predecessor proofs for a spend.
    #[must_use]
    pub fn new(
        secret: Pcd<Pasta, ProductionRank, delegation::NoteSecret>,
        spendable: Pcd<Pasta, ProductionRank, spendable::NoteSpendable>,
        spans: Vec<Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Self {
        Self {
            secret: Box::new(secret),
            spendable: Box::new(spendable),
            spans,
        }
    }

    /// The note secret.
    #[must_use]
    pub const fn secret(&self) -> &Pcd<Pasta, ProductionRank, delegation::NoteSecret> {
        &self.secret
    }

    /// The spendable proof.
    #[must_use]
    pub const fn spendable(&self) -> &Pcd<Pasta, ProductionRank, spendable::NoteSpendable> {
        &self.spendable
    }

    /// The spans from the spendable anchor to the proving target.
    #[must_use]
    pub fn spans(&self) -> &[Pcd<Pasta, ProductionRank, pool::AnchorSpan>] {
        &self.spans
    }
}

impl OutputWitness {
    /// The recipient's key path.
    #[must_use]
    pub const fn zip32_derivation(&self) -> Option<&Zip32Derivation> {
        self.zip32_derivation.as_ref()
    }

    /// The address supplied for display, not authenticated by the effects.
    #[must_use]
    pub fn user_address(&self) -> Option<&str> {
        self.user_address.as_deref()
    }
}

impl Zip32Derivation {
    /// Supply a seed fingerprint and the raw child indices of a key path.
    #[must_use]
    pub const fn new(seed_fingerprint: [u8; 32], derivation_path: Vec<u32>) -> Self {
        Self {
            seed_fingerprint,
            derivation_path,
        }
    }

    /// The seed fingerprint.
    #[must_use]
    pub const fn seed_fingerprint(&self) -> [u8; 32] {
        self.seed_fingerprint
    }

    /// Child indices, including their hardened bits.
    #[must_use]
    pub fn derivation_path(&self) -> &[u32] {
        &self.derivation_path
    }
}
