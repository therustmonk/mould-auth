use std::error;
use std::result;
use authorize::Role;

pub mod map;

pub type Result<T, E> = result::Result<Option<T>, E>;

pub trait TokenChecker<T: Role, E: error::Error> {
    fn get_role_for_token(&mut self, token: &str) -> Result<T, E>;
}

pub trait CredentialChecker<T: Role, E: error::Error> {
    fn get_role_for_credential(&mut self, login: &str, password: &str) -> Result<T, E>;
}
