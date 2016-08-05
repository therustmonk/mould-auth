use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use authorize::{Role, Authorize};
use authorize::checkers::TokenChecker;

/// A handler which use `TokenChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService<TC, R>
    where TC: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<TC>>,
    _role: PhantomData<R>,
}

impl<TC, R> TokenService<TC, R>
    where TC: TokenChecker<R>, R: Role {

    pub fn new(checker: TC) -> Self {
        TokenService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }

}

impl<T, TC, R> Service<T> for TokenService<TC, R>
    where T: Authorize<R>, TC: TokenChecker<R> + 'static, R: Role + 'static {
    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(TokenCheckWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<TC, R>
    where TC: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<TC>>,
    _role: PhantomData<R>,
}

impl<TC, R> TokenCheckWorker<TC, R>
    where TC: TokenChecker<R>, R: Role {
    fn new(checker: Arc<Mutex<TC>>) -> Self {
        TokenCheckWorker { checker: checker, _role: PhantomData }
    }
}

impl<T, TC, R> Worker<T> for TokenCheckWorker<TC, R>
    where T: Authorize<R>, TC: TokenChecker<R>, R: Role {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        let token: String = extract_field!(request, "token");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err(worker::Error::reject("Impossible to check token!"))));
            guard.get_role_for_token(&token)
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
