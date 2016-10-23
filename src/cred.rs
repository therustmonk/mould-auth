use std::convert::From;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use permission::HasPermission;
use checkers::{Role, Authorize, CredentialManager};

pub enum AuthPermission {
    CanAuth,
    CanChange,
}

/// A handler which use `CredentialManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService<C, R>
    where C: CredentialManager<R>, R: Role {

    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> AuthService<C, R>
    where C: CredentialManager<R>, R: Role {

    pub fn new(checker: C) -> Self {
        AuthService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }

}

impl<T, C, R> Service<T> for AuthService<C, R>
    where T: HasPermission<AuthPermission> + Authorize<R>,
          C: CredentialManager<R> + Send + 'static,
          R: Role + Send + Sync + 'static {

    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-login" {
            Box::new(AuthCheckWorker::new(self.checker.clone()))
        } else if request.action == "change-password" {
            Box::new(ChangePasswordWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for auth service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct AuthCheckWorker<C, R>
    where C: CredentialManager<R>,
          R: Role {

    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> AuthCheckWorker<C, R>
    where C: CredentialManager<R>,
          R: Role {

    fn new(checker: Arc<Mutex<C>>) -> Self {
        AuthCheckWorker {
            checker: checker,
            _role: PhantomData,
        }
    }
}

impl<T, C, R> Worker<T> for AuthCheckWorker<C, R>
    where T: HasPermission<AuthPermission> + Authorize<R>,
          C: CredentialManager<R>,
          R: Role {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanAuth);
        let login: String = extract_field!(request, "login");
        let password: String = extract_field!(request, "password");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to check credential!")));
            try!(guard.pick_role(&login, &password))
        };
        ensure_it!(role.is_some(), "Credentials is not valid!");
        session.set_role(role);
        Ok(Shortcut::Done)
    }
}

struct ChangePasswordWorker<C, R>
    where C: CredentialManager<R>,
          R: Role {

    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> ChangePasswordWorker<C, R>
    where C: CredentialManager<R>,
          R: Role {

    fn new(checker: Arc<Mutex<C>>) -> Self {
        ChangePasswordWorker {
            checker: checker,
            _role: PhantomData,
        }
    }
}

impl<T, C, R> Worker<T> for ChangePasswordWorker<C, R>
    where T: HasPermission<AuthPermission> + Authorize<R>,
          C: CredentialManager<R>,
          R: Role {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanChange);
        let password: String = extract_field!(request, "password");
        if let &Some(ref role) = session.as_ref() {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to manage credential!")));
            try!(guard.attach_password(role, &password));
            Ok(Shortcut::Done)
        } else {
            Err(From::from("Can't extract role."))
        }
    }
}

