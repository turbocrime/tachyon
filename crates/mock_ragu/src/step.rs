//! Mock PCD step — a node in the computational graph.
//!
//! This is the mock equivalent of `ragu_pcd::Step`. Instead of circuit
//! synthesis via a `Driver`, the mock step computes output header data
//! directly from the witness and input header data.

use crate::header::Header;

/// Unique index identifying a [`Step`] within an
/// [`Application`](crate::Application).
///
/// Mirrors `ragu_pcd::step::Index`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Index(usize);

impl Index {
    /// Creates a new step index.
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self(value)
    }
}

/// A computation step in the PCD graph.
///
/// Mirrors `ragu_pcd::Step`. Each step defines:
/// - Input headers (`Left`, `Right`) — what data the step consumes
/// - Output header (`Output`) — what data the step produces
/// - Witness and auxiliary data types
///
/// In real Ragu, `witness()` synthesizes a circuit. In the mock,
/// [`synthesize()`](Step::synthesize) computes the output directly.
pub trait Step: Sized + Send + Sync {
    /// Unique index for this step.
    const INDEX: Index;

    /// Witness data provided by the prover.
    type Witness<'source>: Send;

    /// Auxiliary data returned alongside the proof.
    type Aux<'source>: Send;

    /// Left input header type.
    type Left: Header;

    /// Right input header type.
    type Right: Header;

    /// Output header type.
    type Output: Header;

    /// Mock circuit synthesis.
    ///
    /// Computes the output header data from the witness and input headers.
    /// In real Ragu, this would synthesize constraints inside a `Driver`.
    fn synthesize<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> (<Self::Output as Header>::Data<'source>, Self::Aux<'source>);
}
