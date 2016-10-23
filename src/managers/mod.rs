use std::error;
use std::result;

pub mod keyval;

pub trait Role { }

pub trait Authorize<R: Role>: AsRef<Option<R>> {
    fn set_role(&mut self, role: Option<R>) -> Option<R>;
}

pub type Result<T> = result::Result<T, Box<error::Error>>;

pub trait TokenManager<R: Role> {
    fn pick_role(&mut self, token: &str) -> Result<Option<R>>;
    fn acquire_token(&mut self, role: &R) -> Result<String>;
}

pub trait CredentialManager<R: Role> {
    fn pick_role(&mut self, login: &str, password: &str) -> Result<Option<R>>;
    fn attach_password(&mut self, role: &R, password: &str) -> Result<Option<R>>;
}

