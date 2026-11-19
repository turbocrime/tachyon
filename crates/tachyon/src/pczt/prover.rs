use alloc::{collections::BTreeSet, vec, vec::Vec};

use derive_more::{Display, Error};
use ragu::{Pcd, ProductionRank, pasta::Pasta};
use rand_core::CryptoRng;

use super::{Action, ActionWitness, Bundle, MissingField, OpeningField, signing::FeeOpeningError};
use crate::{
    action,
    primitives::effect,
    stamp::{
        self,
        proof::{App, pool},
    },
    value,
};

/// Failure to prove the selected actions.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ProveActionsError {
    /// The selected note's commitment trapdoor is zero.
    #[display("zero rcm at action {_0}")]
    ZeroRcm(#[error(not(source))] usize),
    /// The index is out of range.
    #[display("invalid action index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// The index occurs twice in the selection.
    #[display("repeated action index {_0}")]
    RepeatedIndex(#[error(not(source))] usize),
    /// A stored proof already covers the index.
    #[display("already covered action {_0}")]
    AlreadyCovered(#[error(not(source))] usize),
    /// A proving input is absent.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] MissingField),
    /// The opening does not derive the descriptor.
    #[display("opening mismatch at action {_0}")]
    OpeningMismatch(#[error(not(source))] usize),
    /// Proof construction failed.
    #[display("cannot prove selected actions")]
    Prove(stamp::ProveError),
}

/// Failure to lift an action proof.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum LiftActionsProofError {
    /// The index is outside `actions_proofs`.
    #[display("invalid proof index {_0}")]
    InvalidIndex(#[error(not(source))] usize),
    /// Proof lifting failed.
    #[display("cannot lift action proof")]
    Lift(ragu::Error),
}

/// Failure to apply a fee.
#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum ApplyFeeError {
    /// The maximum fee note's commitment trapdoor is zero.
    #[display("zero maximum fee rcm")]
    ZeroMaxFeeRcm,
    /// A required field is missing.
    #[display("missing {_0}")]
    Missing(#[error(not(source))] MissingField),
    /// The opening does not derive the maximum fee commitment.
    #[display("max fee opening mismatch")]
    MaxFeeOpeningMismatch,
    /// The proofs do not cover every action.
    #[display("incomplete proof coverage")]
    IncompleteCoverage,
    /// An actionless section cannot pay a nonzero fee.
    #[display("nonzero fee for actionless section")]
    NonzeroSeedFee,
    /// Merging action proofs failed.
    #[display("cannot merge action proofs")]
    Merge(stamp::MergeError),
    /// Applying the fee to proven actions failed.
    #[display("cannot apply fee to action proof")]
    Fee(stamp::FeeError),
    /// Seeding a stamp without actions failed.
    #[display("cannot seed actionless stamp")]
    Seed(stamp::SeedError),
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "proving entry points are defined together"
)]
impl Bundle {
    /// Prove the selected actions and append an `ActionsProof`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid selection, unavailable or inconsistent
    /// openings, or failed proving.
    #[expect(clippy::ref_patterns, reason = "borrow the spend witness")]
    pub fn prove_actions<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        indices: &[usize],
    ) -> Result<(), ProveActionsError> {
        let anchor = self
            .anchor
            .ok_or(ProveActionsError::Missing(MissingField::Anchor))?;
        let mut selected = BTreeSet::new();
        for &index in indices {
            if !selected.insert(index) {
                return Err(ProveActionsError::RepeatedIndex(index));
            }
        }
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        let mut pcds = Vec::new();
        for index in selected {
            let action = self
                .actions
                .get(index)
                .ok_or(ProveActionsError::InvalidIndex(index))?;
            let desc = action.descriptor;
            if self
                .actions_proofs
                .iter()
                .any(|proof| proof.pairs.contains_key(&desc))
            {
                return Err(ProveActionsError::AlreadyCovered(index));
            }
            let missing = |field| ProveActionsError::Missing(MissingField::Action(index, field));
            let theta = action.theta.ok_or_else(|| missing(OpeningField::Theta))?;
            let rcv = action.rcv.ok_or_else(|| missing(OpeningField::Rcv))?;
            let check = |result: Option<_>| {
                let derived = result.ok_or(ProveActionsError::ZeroRcm(index))?;
                if derived == desc {
                    Ok(())
                } else {
                    Err(ProveActionsError::OpeningMismatch(index))
                }
            };
            match *action
                .witness
                .as_ref()
                .ok_or_else(|| missing(OpeningField::Witness))?
            {
                ActionWitness::Spend(ref spend) => {
                    let pak = spend.pak().ok_or_else(|| missing(OpeningField::Pak))?;
                    let lineage = spend
                        .lineage
                        .as_ref()
                        .ok_or_else(|| missing(OpeningField::Lineage))?;
                    let (_, note, _) = *lineage.secret.data();
                    check(Action::checked_descriptor(action::Plan::<effect::Spend> {
                        note,
                        theta,
                        rcv,
                        authority: pak.ak,
                    }))?;
                    spends.push((desc, theta, rcv));
                    pcds.push((
                        pak,
                        lineage.secret().clone(),
                        lineage.spendable().clone(),
                        lineage.spans.clone(),
                    ));
                },
                ActionWitness::Output(_) => {
                    let opening = action.opening::<effect::Output>(()).map_err(missing)?;
                    check(Action::checked_descriptor(opening))?;
                    outputs.push((desc, theta, opening.note, rcv));
                },
            }
        }
        let proof = stamp::ActionsPlan::new(spends, outputs, anchor)
            .prove(rng, app, pcds)
            .map_err(ProveActionsError::Prove)?;
        self.actions_proofs.push(proof);
        self.actions_proofs
            .sort_by(|left, right| left.pairs.keys().next().cmp(&right.pairs.keys().next()));
        Ok(())
    }

    /// Advance one entry of `actions_proofs` to a later anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid index or failed lifting.
    pub fn lift_actions_proof<RNG: CryptoRng>(
        &mut self,
        index: usize,
        rng: &mut RNG,
        app: &App<'_>,
        spans: Vec<Pcd<Pasta, ProductionRank, pool::AnchorSpan>>,
    ) -> Result<(), LiftActionsProofError> {
        let proof = self
            .actions_proofs
            .get_mut(index)
            .ok_or(LiftActionsProofError::InvalidIndex(index))?;
        *proof = proof
            .clone()
            .lift(rng, app, spans)
            .map_err(LiftActionsProofError::Lift)?;
        Ok(())
    }

    /// Apply the fee and retain one `ActionsProof` for later fee changes.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete coverage, invalid fee opening or failed
    /// proving.
    pub fn apply_fee<RNG: CryptoRng>(
        &mut self,
        rng: &mut RNG,
        app: &App<'_>,
        fee: value::Positive,
    ) -> Result<(), ApplyFeeError> {
        let actionless = self.actions.is_empty();
        let note = self.checked_fee_opening().map_err(|err| match err {
            FeeOpeningError::Missing(field) => ApplyFeeError::Missing(MissingField::MaxFee(field)),
            FeeOpeningError::CommitmentMismatch => ApplyFeeError::MaxFeeOpeningMismatch,
            FeeOpeningError::ZeroRcm => ApplyFeeError::ZeroMaxFeeRcm,
        })?;
        if actionless {
            if fee != value::Positive::ZERO {
                return Err(ApplyFeeError::NonzeroSeedFee);
            }
            let anchor = self
                .anchor
                .ok_or(ApplyFeeError::Missing(MissingField::Anchor))?;
            let parts =
                stamp::AutonomeParts::seed(rng, app, note, anchor).map_err(ApplyFeeError::Seed)?;
            self.autonome_parts = Some(parts);
            return Ok(());
        }
        let Some((first, rest)) = self.actions_proofs.split_first() else {
            return Err(ApplyFeeError::IncompleteCoverage);
        };
        if first.pairs.len() + rest.iter().map(|proof| proof.pairs.len()).sum::<usize>()
            != self.actions.len()
        {
            return Err(ApplyFeeError::IncompleteCoverage);
        }
        let merged = rest
            .iter()
            .cloned()
            .try_fold(first.clone(), |left, right| left.merge(rng, app, right))
            .map_err(ApplyFeeError::Merge)?;
        let parts = merged
            .clone()
            .fee(rng, app, note, fee)
            .map_err(ApplyFeeError::Fee)?;
        self.actions_proofs = vec![merged];
        self.autonome_parts = Some(parts);
        Ok(())
    }
}
