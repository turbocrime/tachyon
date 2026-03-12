//! Mock PCD step — mirrors `ragu_pcd::Step`.

use crate::{error::Result, header::Header};

/// Mirrors `ragu_pcd::step::Index`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Index(usize);

impl Index {
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self(value)
    }
}

/// Mirrors `ragu_pcd::Step`.
pub trait Step: Sized + Send + Sync {
    const INDEX: Index;
    type Witness<'source>: Send;
    type Aux<'source>: Send;
    type Left: Header;
    type Right: Header;
    type Output: Header;

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)>;
}
