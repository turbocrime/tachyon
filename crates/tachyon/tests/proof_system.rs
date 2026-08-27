//! Integration coverage for the registered Ragu application.

#[cfg(test)]
mod tests {
    use core::ptr;

    use zcash_tachyon::stamp::proof::PROOF_SYSTEM;

    /// Registration of the fixed step list happens lazily and panics on
    /// failure, so forcing initialization is the assertion.
    #[test]
    fn proof_system_registers_the_fixed_step_list() {
        let first: &'static _ = &*PROOF_SYSTEM;
        let second: &'static _ = &*PROOF_SYSTEM;

        assert!(ptr::eq(first, second), "PROOF_SYSTEM must be a singleton");
    }
}
