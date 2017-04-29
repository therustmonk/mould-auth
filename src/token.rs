use std::marker::PhantomData;
use mould::prelude::*;
use permission::HasPermission;
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

impl<T, R: 'static> service::Service<T> for TokenService<R>
    where T: Session + HasPermission<TokenPermission> + Manager<R>, R: Role,
{
    fn route(&self, action: &str) -> service::Result<service::Action<T>> {
        match action {
            "do-login" => Ok(do_login::action()),
            "acquire-new" => Ok(acquire_new::action()),
            _ => Err(service::ErrorKind::ActionNotFound.into()),
        }
    }
}

mod do_login {
    use super::*;

    pub fn action<T, R>() -> service::Action<T>
        where T: Session + HasPermission<TokenPermission> + Manager<R>, R: Role,
    {
        service::Action::from_worker(Worker::new())
    }

    struct Worker<R> {
        _role: PhantomData<R>,
    }

    impl<R> Worker<R> {
        fn new() -> Self {
            Worker {
                _role: PhantomData,
            }
        }
    }

    #[derive(Deserialize)]
    struct Request {
        token: String,
    }

    impl<T, R> worker::Worker<T> for Worker<R>
        where T: Session + HasPermission<TokenPermission> + Manager<R>, R: Role,
    {
        type Request = Request;
        type In = worker::Any;
        type Out = worker::Any;

        fn prepare(&mut self, session: &mut T, request: Self::Request) -> worker::Result<Shortcut> {
            permission_required!(session, TokenPermission::CanAuth);
            if session.set_role(&request.token)? {
                Ok(Shortcut::Done)
            } else {
                Ok(Shortcut::Reject("wrong token".into()))
            }
        }
    }
}

mod acquire_new {
    use super::*;

    pub fn action<T, R>() -> service::Action<T>
        where T: Session + HasPermission<TokenPermission> + Manager<R>, R: Role,
    {
        service::Action::from_worker(Worker::new())
    }

    struct Worker<R> {
        token: Option<String>,
        _role: PhantomData<R>,
    }

    impl<R> Worker<R> {

        fn new() -> Self {
            Worker {
                token: None,
                _role: PhantomData,
            }
        }
    }

    #[derive(Serialize)]
    struct Out {
        token: String,
    }

    impl<T, R> worker::Worker<T> for Worker<R>
        where T: Session + HasPermission<TokenPermission> + Manager<R>, R: Role,
    {
        type Request = worker::Any;
        type In = worker::Any;
        type Out = Out;

        fn prepare(&mut self, session: &mut T, _: Self::Request) -> worker::Result<Shortcut> {
            permission_required!(session, TokenPermission::CanAcquire);
            self.token = Some(session.acquire_token()?);
            Ok(Shortcut::Tuned)
        }

        fn realize(&mut self, _: &mut T, _: Option<Self::In>) -> worker::Result<Realize<Self::Out>> {
            let token = self.token.take().expect("token expected here");
            Ok(Realize::OneItemAndDone(Out { token }))
        }
    }

}
