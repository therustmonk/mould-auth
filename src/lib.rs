//! Mould plugin for token authentication.

extern crate mould;

pub mod token;

use mould::session::SessionData;

/// Marker trait of role.
/// Implement it for your struct or enum to represent roles in your services.
pub trait Role: 'static { }

/// A session feature to be authorized.
pub trait Authorize<R: Role>: SessionData {
    fn set_role(&mut self, role: Option<R>) -> Option<R>;
}
