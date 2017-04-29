//! Mould plugin for token authentication.

extern crate mould;
pub extern crate permission;
#[macro_use] extern crate serde_derive;

#[macro_use]
mod macros;
pub mod token;
pub mod cred;

pub use token::*;
pub use cred::*;

pub trait Role: 'static { }
