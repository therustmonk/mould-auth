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

impl<T, R> Service<T> for AuthService<R>
    where T: HasPermission<AuthPermission> + Manager<R>, R: Role {

    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-login" {
            Box::new(AuthCheckWorker::new())
        } else if request.action == "change-password" {
            Box::new(ChangePasswordWorker::new())
        } else {
            let msg = format!("Unknown action '{}' for auth service!", request.action);
            Box::new(RejectWorker::new(msg))
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
        let login: String = extract_field!(request, "login");
        let password: String = extract_field!(request, "password");
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

