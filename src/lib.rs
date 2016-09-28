//! Mould plugin for token authentication.

#[macro_use(extract_field)]
extern crate mould;
pub extern crate authorize;

mod token;

pub use token::*;
