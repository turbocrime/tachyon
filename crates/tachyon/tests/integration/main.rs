#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::integer_division_remainder_used,
    clippy::integer_division,
    clippy::missing_assert_message,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    reason = "test code"
)]

#[cfg(test)]
mod bundle;
#[cfg(test)]
mod evidence;
#[cfg(test)]
mod fee;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod pczt_mirror_compact;
#[cfg(test)]
mod pczt_mirror_effects;
#[cfg(test)]
mod pczt_mirror_lineage;
#[cfg(test)]
mod pczt_mirror_proofs;
#[cfg(test)]
mod pczt_mirror_witnesses;
#[cfg(test)]
mod pczt_proving;
#[cfg(test)]
mod pczt_review;
#[cfg(test)]
mod pczt_signing;
#[cfg(test)]
mod pczt_update;
#[cfg(test)]
mod proof;
#[cfg(test)]
mod qr;
#[cfg(test)]
mod stamp;
#[cfg(test)]
mod summary;
#[cfg(test)]
mod unmerge;
