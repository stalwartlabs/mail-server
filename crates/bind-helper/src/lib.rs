mod addr;

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::*;

#[cfg(not(unix))]
pub struct Helper;
