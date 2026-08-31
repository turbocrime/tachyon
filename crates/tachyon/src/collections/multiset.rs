extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::Fp;
use ragu::{Polynomial, poly_with_roots};

/// Encode the provided members as roots.
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial {
    let roots: Vec<Fp> = members.into_iter().collect();
    Polynomial::from_coeffs(poly_with_roots(&roots))
}
