//! Vendored 32-bit-word gadget (nova's crate-private `gadgets::uint32` +
//! `multieq`, MIT), extended with `and`/`or`/`not` for RIPEMD160.
pub(crate) mod multieq;
pub mod word;
