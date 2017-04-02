use mould::prelude::*;
use permission::HasPermission;

pub trait Manager {
    fn set_role(&mut self, token: &str) -> Result<(), &str>;
    fn acquire_token(&mut self) -> Result<String, &str>;
}

pub enum TokenPermission {
    CanAuth,
    CanAcquire,
}

/// A handler which use `TokenManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by token
pub struct TokenService { }

impl TokenService {
    pub fn new() -> Self {
        TokenService {
        } }
}

impl<T> Service<T> for TokenService
    where T: HasPermission<TokenPermission> + Manager {

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

struct TokenCheckWorker { }

impl TokenCheckWorker {
    fn new() -> Self {
        TokenCheckWorker { }
    }
}

impl<T> Worker<T> for TokenCheckWorker
    where T: HasPermission<TokenPermission> + Manager {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAuth);
        let token: String = extract_field!(request, "token");
        session.set_role(&token)?;
        Ok(Shortcut::Done)
    }
}

struct AcquireTokenWorker {
    token: Option<String>,
}

impl AcquireTokenWorker {

    fn new() -> Self {
        AcquireTokenWorker {
            token: None,
        }
    }
}

impl<T> Worker<T> for AcquireTokenWorker
    where T: HasPermission<TokenPermission> + Manager {

    fn prepare(&mut self, session: &mut T, _: Request) -> worker::Result<Shortcut> {
        permission_required!(session, TokenPermission::CanAcquire);
        self.token = Some(session.acquire_token()?);
        Ok(Shortcut::Tuned)
    }

    fn realize(&mut self, _: &mut T, _: Option<Request>) -> worker::Result<Realize> {
        let token = self.token.take().expect("token expected here");
        Ok(Realize::OneItemAndDone(mould_object!{
            "token" => token
        }))
    }
}

