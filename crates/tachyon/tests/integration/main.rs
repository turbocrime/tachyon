#![allow(
    dead_code,
    unused,
    clippy::as_conversions,
    clippy::expect_used,
    clippy::missing_assert_message,
    clippy::must_use_candidate,
    clippy::partial_pub_fields,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    missing_debug_implementations,
    clippy::indexing_slicing,
    clippy::type_complexity,
    missing_docs,
    unreachable_pub,
    reason = "test code"
)]

#[cfg(test)]
mod bundle_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod stamp_tests;
