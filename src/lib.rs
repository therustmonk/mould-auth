//! Mould plugin for token authentication.

extern crate mould;

pub mod token;

use mould::Session;

/// Marker trait of role.
/// Implement it for your struct or enum to represent roles in your services.
pub trait Role: 'static { }

/// A session feature to be authorized.
pub trait Authorize<T: Role>: Session {
    fn set_role(&mut self, role: Option<T>) -> Option<T>;
}
