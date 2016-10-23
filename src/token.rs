use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use mould::prelude::*;
use permission::HasPermission;
use checkers::{Role, Authorize, TokenManager};

pub enum TokenPermission {
    CanAuth,
    CanAcquire,
}

/// A handler which use `TokenManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService<C, R>
    where C: TokenManager<R>,
          R: Role {

    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> TokenService<C, R>
    where C: TokenManager<R>,
          R: Role {

    pub fn new(checker: C) -> Self {
        TokenService {
            checker: Arc::new(Mutex::new(checker)),
            _role: PhantomData,
        }
    }
}

impl<T, C, R> Service<T> for TokenService<C, R>
    where T: HasPermission<TokenPermission> + Authorize<R>,
          C: TokenManager<R> + Send + 'static,
          R: Role + Send + Sync + 'static {

    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-auth" {
            Box::new(TokenCheckWorker::new(self.checker.clone()))
        } else if request.action == "acquire-new" {
            Box::new(AcquireTokenWorker::new(self.checker.clone()))
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<C, R>
    where C: TokenManager<R>, R: Role {

    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> TokenCheckWorker<C, R>
    where C: TokenManager<R>, R: Role {

    fn new(checker: Arc<Mutex<C>>) -> Self {
        TokenCheckWorker {
            checker: checker,
            _role: PhantomData,
        }
    }
}

impl<T, C, R> Worker<T> for TokenCheckWorker<C, R>
    where T: HasPermission<TokenPermission> + Authorize<R>,
          C: TokenManager<R>,
          R: Role {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAuth);
        let token: String = extract_field!(request, "token");
        let role = {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to check token!")));
            try!(guard.pick_role(&token))
        };
        ensure_it!(role.is_some(), "Token is not valid!");
        session.set_role(role);
        Ok(Shortcut::Done)
    }
}

struct AcquireTokenWorker<C, R> {
    token: Option<String>,
    checker: Arc<Mutex<C>>,
    _role: PhantomData<R>,
}

impl<C, R> AcquireTokenWorker<C, R>
    where C: TokenManager<R>, R: Role {

    fn new(checker: Arc<Mutex<C>>) -> Self {
        AcquireTokenWorker {
            token: None,
            checker: checker,
            _role: PhantomData,
        }
    }
}

impl<T, C, R> Worker<T> for AcquireTokenWorker<C, R>
    where T: HasPermission<TokenPermission> + Authorize<R>,
          C: TokenManager<R>,
          R: Role {

    fn prepare(&mut self, session: &mut T, _: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAcquire);
        if let &Some(ref role) = session.as_ref() {
            let mut guard = try!(self.checker.lock()
                .or(Err("Impossible to manage token!")));
            let token = try!(guard.acquire_token(role));
            self.token = Some(token);
            Ok(Shortcut::Tuned)
        } else {
            Err(From::from("Can't extract role."))
        }
    }

    fn realize(&mut self, _: &mut T, _: Option<Request>) -> worker::Result<Realize> {
        let token = self.token.take().expect("token expected here");
        Ok(Realize::OneItemAndDone(mould_object!{
            "token" => token
        }))
    }
}

