use std::error;
use std::result;
//use std::str::FromStr;
//use identify::Identified;

//pub mod map;

pub trait Role /*: Identified<T>*/ {
}

pub trait Authorize<R: Role>: AsRef<Option<R>> {
    fn set_role(&mut self, role: Option<R>) -> Option<R>;
}

pub type Result<T> = result::Result<T, Box<error::Error>>;

/*
pub trait Credential {
    fn locator(&self) -> &str;
    fn pass(&self) -> &str;
}

pub trait Generator<C: Credential> {
    fn from_pair(&mut self, locator: &str, pass: &str) -> C;
}
*/

//pub type Token = Credential + ToString + FromStr;

pub trait TokenManager<R: Role> {
    fn pick_role(&mut self, token: &str) -> Result<Option<R>>;
    fn acquire_token(&mut self, role: &Role) -> Result<String>;
}

pub trait CredentialManager<R: Role> {
    fn pick_role(&mut self, login: &str, password: &str) -> Result<Option<R>>;
    fn attach_password(&mut self, role: &R, password: &str) -> Result<Option<R>>;
}

pub trait Crypt {
    fn hash(pass: &str) -> String;
    fn verify(pass: &str, digest: &str) -> bool;
}

