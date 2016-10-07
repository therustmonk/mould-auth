use std::error::Error;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use authorize::{Role, Authorize};
use authorize::checkers::TokenChecker;

/// A handler which use `TokenChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService<C, R, E>
    where C: TokenChecker<R, E>, R: Role, E: Error {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
    _error: PhantomData<E>,
}

impl<C, R, E> TokenService<C, R, E>
    where C: TokenChecker<R, E>, R: Role, E: Error {

    pub fn new(checker: C) -> Self {
        TokenService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
            _error: PhantomData,
        }
    }
}

impl<T, C, R, E> Service<T> for TokenService<C, R, E>
    where T: Authorize<R>,
          C: TokenChecker<R, E> + Send + 'static,
          R: Role + Send + Sync + 'static,
          E: Error + Send + Sync + 'static {
    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(TokenCheckWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<C, R, E>
    where C: TokenChecker<R, E>, R: Role, E: Error {
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
    _error: PhantomData<E>,
}

impl<C, R, E> TokenCheckWorker<C, R, E>
    where C: TokenChecker<R, E>, R: Role, E: Error {
    fn new(checker: Arc<Mutex<C>>) -> Self {
        TokenCheckWorker {
            checker: checker,
            _role: PhantomData,
            _error: PhantomData,
        }
    }
}

impl<T, C, R, E> Worker<T> for TokenCheckWorker<C, R, E>
    where T: Authorize<R>, C: TokenChecker<R, E>, R: Role, E: Error + 'static {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        let token: String = extract_field!(request, "token");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to check token!")));
            try!(guard.get_role_for_token(&token))
        };
        ensure_it!(role.is_some(), "Token is not valid!");
        session.set_role(role);
        Ok(Shortcut::Done)
    }
}
