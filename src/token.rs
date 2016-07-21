use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use super::{Role, Authorize};

/// A generic token checking interface.
pub trait TokenChecker<R: Role>: 'static {
    fn get_role_for_token(&mut self, token: &str) -> Option<R>;
}

/// A handler which use `TokenChecker` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenHandler<TC, R>
    where TC: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<TC>>,
    _role: PhantomData<R>,
}

impl<TC, R> TokenHandler<TC, R>
    where TC: TokenChecker<R>, R: Role {

    pub fn new(checker: TC) -> Self {
        TokenHandler {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }

}

impl<CTX, TC, R> Handler<CTX> for TokenHandler<TC, R>
    where CTX: Authorize<R>, TC: TokenChecker<R>, R: Role {
    fn build(&self, mut request: Request) -> Box<Worker<CTX>> {
        if request.action == "do-auth" {
            Box::new(TokenCheckWorker {
                checker: self.checker.clone(),
                token: request.extract("token"),
                _role: PhantomData,
            })
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<TC, R>
    where TC: TokenChecker<R>, R: Role {
    checker: Arc<Mutex<TC>>,
    token: Option<String>,
    _role: PhantomData<R>,
}

impl<CTX, TC, R> Worker<CTX> for TokenCheckWorker<TC, R>
    where CTX: Authorize<R>, TC: TokenChecker<R>, R: Role {
    fn shortcut(&mut self, session: &mut CTX) -> WorkerResult<Shortcut> {
        let token = try!(self.token.take()
            .ok_or(WorkerError::reject("No token provided!")));
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err(WorkerError::reject("Impossible to check token!"))));
            guard.get_role_for_token(&token)
        };
        let success = role.is_some();
        session.set_role(role);
        if success {
            Ok(Shortcut::Done)
        } else {
            Err(WorkerError::reject("Token is not valid!"))
        }
    }
}
