use std::marker::PhantomData;
use mould::prelude::*;
use permission::HasPermission;
use super::Role;

pub trait Manager<R: Role> {
    fn set_role(&mut self, login: &str, password: &str) -> Result<bool, &str>;
    fn attach_password(&mut self, password: &str) -> Result<(), &str>;
}

pub enum AuthPermission {
    CanAuth,
    CanChange,
}

/// A handler which use `CredentialManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService<R> {
    _role: PhantomData<R>,
}

impl<R> AuthService<R> {
    pub fn new() -> Self {
        AuthService {
            _role: PhantomData,
        }
    }
}

unsafe impl<R> Sync for AuthService<R> { }
unsafe impl<R> Send for AuthService<R> { }

impl<T, R> service::Service<T> for AuthService<R>
    where T: HasPermission<AuthPermission> + Manager<R>, R: Role {

    fn route(&self, request: &Request) -> service::Result<Box<Worker<T>>> {
        match request.action.as_ref() {
            "do-login" => Ok(Box::new(AuthCheckWorker::new())),
            "change-password" => Ok(Box::new(ChangePasswordWorker::new())),
            _ => Err(service::ErrorKind::ActionNotFound.into()),
        }
    }
}

struct AuthCheckWorker<R> {
    _role: PhantomData<R>,
}

impl<R> AuthCheckWorker<R> {
    fn new() -> Self {
        AuthCheckWorker {
            _role: PhantomData,
        }
    }
}

impl<T, R> Worker<T> for AuthCheckWorker<R>
    where T: HasPermission<AuthPermission> + Manager<R>, R: Role {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanAuth);
        let login: String = request.extract("login")?;
        let password: String = request.extract("password")?;
        if session.set_role(&login, &password)? {
            Ok(Shortcut::Done)
        } else {
            Ok(Shortcut::Reject("wrong credentials".into()))
        }
    }
}

struct ChangePasswordWorker<R> {
    _role: PhantomData<R>,
}

impl<R> ChangePasswordWorker<R> {
    fn new() -> Self {
        ChangePasswordWorker {
            _role: PhantomData,
        }
    }
}

impl<T, R> Worker<T> for ChangePasswordWorker<R>
    where T: HasPermission<AuthPermission> + Manager<R>, R: Role {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanChange);
        let password: String = request.extract("password")?;
        session.attach_password(&password)?;
        Ok(Shortcut::Done)
    }
}

