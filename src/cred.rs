use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use authorize::{Role, Authorize};
use authorize::checkers::CredentialChecker;

/// A handler which use `CredentialChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService<C, R>
    where C: CredentialChecker<R>, R: Role {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> AuthService<C, R>
    where C: CredentialChecker<R>, R: Role {

    pub fn new(checker: C) -> Self {
        AuthService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }

}

impl<T, C, R> Service<T> for AuthService<C, R>
    where T: Authorize<R>, C: CredentialChecker<R> + 'static, R: Role + 'static {
    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(AuthCheckWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct AuthCheckWorker<C, R>
    where C: CredentialChecker<R>, R: Role {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> AuthCheckWorker<C, R>
    where C: CredentialChecker<R>, R: Role {
    fn new(checker: Arc<Mutex<C>>) -> Self {
        AuthCheckWorker { checker: checker, _role: PhantomData }
    }
}

impl<T, C, R> Worker<T> for AuthCheckWorker<C, R>
    where T: Authorize<R>, C: CredentialChecker<R>, R: Role {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        let login: String = extract_field!(request, "login");
        let password: String = extract_field!(request, "password");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err(worker::Error::reject("Impossible to check credential!"))));
            guard.get_role_for_credential(&login, &password)
        };
        let success = role.is_some();
        session.set_role(role);
        if success {
            Ok(Shortcut::Done)
        } else {
            Err(worker::Error::reject("Token is not valid!"))
        }
    }
}

