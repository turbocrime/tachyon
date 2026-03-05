use pasta_curves::Fp;

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as **flavor** in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$.
/// Different epochs produce different nullifiers for the same note,
/// enabling range-restricted delegation via the GGM tree PRF.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Epoch(Fp);

impl From<Fp> for Epoch {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<u32> for Epoch {
    fn from(val: u32) -> Self {
        Self(Fp::from(u64::from(val)))
    }
}

impl From<Epoch> for Fp {
    fn from(ec: Epoch) -> Self {
        ec.0
    }
}

impl Epoch {
    /// Extract as `u32` for GGM tree indexing.
    ///
    /// Returns `None` if the epoch exceeds `u32::MAX`.
    #[must_use]
    pub fn as_u32(self) -> Option<u32> {
        use ff::PrimeField as _;
        let repr = self.0.to_repr();
        if repr[4..].iter().all(|&b| b == 0) {
            Some(u32::from_le_bytes(
                repr[..4].try_into().expect("4-byte slice"),
            ))
        } else {
            None
        }
    }
}
