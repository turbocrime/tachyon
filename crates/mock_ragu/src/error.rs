//! Mock error types mirroring `ragu_core`.

use core::{error, fmt, result};

/// Alias for [`core::result::Result<T, Error>`].
///
/// Mirrors `ragu_core::Result`.
pub type Result<T> = result::Result<T, Error>;

/// Mock of `ragu_core::Error`.
#[derive(Debug)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mock ragu error")
    }
}

impl error::Error for Error {}
