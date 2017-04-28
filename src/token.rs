use std::marker::PhantomData;
use mould::prelude::*;
use permission::HasPermission;
use serde_json::{Map, Value};
use super::Role;

pub trait Manager<R: Role> {
    fn set_role(&mut self, token: &str) -> Result<bool, &str>;
    fn acquire_token(&mut self) -> Result<String, &str>;
}

pub enum TokenPermission {
    CanAuth,
    CanAcquire,
}

/// A handler which use `TokenManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService<R> {
    _role: PhantomData<R>,
}

unsafe impl<R> Sync for TokenService<R> { }
unsafe impl<R> Send for TokenService<R> { }

impl<R> TokenService<R> {
    pub fn new() -> Self {
        TokenService {
            _role: PhantomData,
        }
    }
}

impl<T, R> Service<T> for TokenService<R>
    where T: HasPermission<TokenPermission> + Manager<R>, R: Role {

    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-login" {
            Box::new(TokenCheckWorker::new())
        } else if request.action == "acquire-new" {
            Box::new(AcquireTokenWorker::new())
        } else {
            let msg = format!("Unknown action '{}' for token service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct TokenCheckWorker<R> {
    _role: PhantomData<R>,
}

impl<R> TokenCheckWorker<R> {
    fn new() -> Self {
        TokenCheckWorker {
            _role: PhantomData,
        }
    }
}

impl<T, R> Worker<T> for TokenCheckWorker<R>
    where T: HasPermission<TokenPermission> + Manager<R>, R: Role {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAuth);
        let token: String = extract_field!(request, "token");
        if session.set_role(&token)? {
            Ok(Shortcut::Done)
        } else {
            Ok(Shortcut::Reject("wrong token".into()))
        }
    }
}

struct AcquireTokenWorker<R> {
    token: Option<String>,
    _role: PhantomData<R>,
}

impl<R> AcquireTokenWorker<R> {

    fn new() -> Self {
        AcquireTokenWorker {
            token: None,
            _role: PhantomData,
        }
    }
}

struct TokenAnswer {
    token: String,
}

impl Into<Map<String, Value>> for TokenAnswer {
    fn into(self) -> Map<String, Value> {
        let mut result = Map::new();
        result.insert("token".into(), self.token.into());
        result
    }
}

impl<T, R> Worker<T> for AcquireTokenWorker<R>
    where T: HasPermission<TokenPermission> + Manager<R>, R: Role {

    fn prepare(&mut self, session: &mut T, _: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAcquire);
        self.token = Some(session.acquire_token()?);
        Ok(Shortcut::Tuned)
    }

    fn realize(&mut self, _: &mut T, _: Option<Request>) -> worker::Result<Realize> {
        let token = self.token.take().expect("token expected here");
        let answer = TokenAnswer {
            token: token,
        };
        Ok(Realize::OneItemAndDone(answer.into()))
    }
}

