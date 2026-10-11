//! The fuzz workspace's library half: the byte-input target bodies ([`targets`]) and the seed corpus
//! generated from the production types ([`seeds`]). The byte-input `fuzz_targets/*.rs` binaries delegate
//! to [`targets`] so the same code runs under libFuzzer and, in [`seeds`]' tests, in-process over every
//! generated seed; the two `Arbitrary` binaries carry their own bodies. This crate never links libfuzzer-sys itself: only the binaries do, so `cargo test`
//! here runs on stable.

pub mod seeds;
pub mod targets;
