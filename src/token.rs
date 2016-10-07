use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use authorize::{Role, Authorize};
use authorize::checkers::TokenChecker;

/// A handler which use `TokenChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService<C, R>
    where C: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> TokenService<C, R>
    where C: TokenChecker<R>, R: Role {

    pub fn new(checker: C) -> Self {
        TokenService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }

}

impl<T, C, R> Service<T> for TokenService<C, R>
    where T: Authorize<R>, C: TokenChecker<R> + 'static, R: Role + 'static {
    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(TokenCheckWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<C, R>
    where C: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> TokenCheckWorker<C, R>
    where C: TokenChecker<R>, R: Role {
    fn new(checker: Arc<Mutex<C>>) -> Self {
        TokenCheckWorker { checker: checker, _role: PhantomData }
    }
}

impl<T, C, R> Worker<T> for TokenCheckWorker<C, R>
    where T: Authorize<R>, C: TokenChecker<R>, R: Role {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        let token: String = extract_field!(request, "token");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to check token!")));
            guard.get_role_for_token(&token)
        };
        ensure_it!(role.is_some(), "Token is not valid!");
        session.set_role(role);
        Ok(Shortcut::Done)
    }
}
