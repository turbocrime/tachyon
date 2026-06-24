extern crate alloc;

use alloc::vec::Vec;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use group::Group as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::note::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence $N$ (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqCommit {
    /// The identity commitment: the commit of the empty nullifier sequence.
    #[must_use]
    pub fn identity() -> Self {
        Self(Eq::identity())
    }
}

impl NfSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<NfSeqPoly> for Polynomial {
    fn from(poly: NfSeqPoly) -> Self {
        poly.0
    }
}

impl<I: IntoIterator<Item = Nullifier>> From<I> for NfSeqPoly {
    fn from(nfs: I) -> Self {
        let coeffs: Vec<Fp> = nfs.into_iter().map(|nf| *nf.as_ref()).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}
