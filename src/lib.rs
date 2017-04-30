//! Mould plugin for token authentication.

extern crate mould;
#[macro_use] extern crate serde_derive;

pub mod token;
pub mod cred;

pub use token::*;
pub use cred::*;

pub trait Role: 'static { }
