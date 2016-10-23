//! Mould plugin for token authentication.

#[macro_use]
extern crate mould;
pub extern crate permission;
pub extern crate identify;

#[macro_use]
mod macros;
mod token;
mod cred;
pub mod managers;

pub use token::*;
pub use cred::*;
pub use managers::*;

