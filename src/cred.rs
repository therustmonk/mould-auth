use std::error::Error;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use authorize::{Role, Authorize};
use authorize::checkers::CredentialChecker;

/// A handler which use `CredentialChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService<C, R, E>
    where C: CredentialChecker<R, E>, R: Role, E: Error {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
    _error: PhantomData<E>,
}

impl<C, R, E> AuthService<C, R, E>
    where C: CredentialChecker<R, E>, R: Role, E: Error {

    pub fn new(checker: C) -> Self {
        AuthService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
            _error: PhantomData,
        }
    }

}

impl<T, C, R, E> Service<T> for AuthService<C, R, E>
    where T: Authorize<R>,
          C: CredentialChecker<R, E> + Send + 'static,
          R: Role + Send + Sync + 'static,
          E: Error + Send + Sync + 'static {
    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(AuthCheckWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct AuthCheckWorker<C, R, E>
    where C: CredentialChecker<R, E>, R: Role, E: Error {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
    _error: PhantomData<E>,
}

impl<C, R, E> AuthCheckWorker<C, R, E>
    where C: CredentialChecker<R, E>, R: Role, E: Error {
    fn new(checker: Arc<Mutex<C>>) -> Self {
        AuthCheckWorker {
            checker: checker,
            _role: PhantomData,
            _error: PhantomData,
        }
    }
}

impl<T, C, R, E> Worker<T> for AuthCheckWorker<C, R, E>
    where T: Authorize<R>, C: CredentialChecker<R, E>, R: Role, E: Error + 'static {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        let login: String = extract_field!(request, "login");
        let password: String = extract_field!(request, "password");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to check credential!")));
            try!(guard.get_role_for_credential(&login, &password))
        };
        ensure_it!(role.is_some(), "Credentials is not valid!");
        session.set_role(role);
        Ok(Shortcut::Done)
    }
}

