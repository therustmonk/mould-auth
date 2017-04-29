use std::marker::PhantomData;
use mould::prelude::*;
use permission::HasPermission;
use super::Role;

pub trait Manager<R: Role> {
    fn set_role(&mut self, login: &str, password: &str) -> Result<bool, &str>;
    fn attach_password(&mut self, password: &str) -> Result<(), &str>;
}

pub enum AuthPermission {
    CanAuth,
    CanChange,
}

/// A handler which use `CredentialManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService<R> {
    _role: PhantomData<R>,
}

impl<R> AuthService<R> {
    pub fn new() -> Self {
        AuthService {
            _role: PhantomData,
        }
    }
}

unsafe impl<R> Sync for AuthService<R> { }
unsafe impl<R> Send for AuthService<R> { }

impl<T, R: 'static> service::Service<T> for AuthService<R>
    where T: Session + HasPermission<AuthPermission> + Manager<R>, R: Role,
{
    fn route(&self, action: &str) -> service::Result<service::Action<T>> {
        match action {
            "do-login" => Ok(do_login::action()),
            "change-password" => Ok(change_password::action()),
            _ => Err(service::ErrorKind::ActionNotFound.into()),
        }
    }
}

mod do_login {
    use super::*;

    pub fn action<T, R>() -> service::Action<T>
        where T: Session + HasPermission<AuthPermission> + Manager<R>, R: Role,
    {
        let worker = Worker {
            _role: PhantomData,
        };
        service::Action::from_worker(worker)
    }

    struct Worker<R> {
        _role: PhantomData<R>,
    }

    #[derive(Deserialize)]
    struct Request {
        login: String,
        password: String,
    }

    impl<T, R> worker::Worker<T> for Worker<R>
        where T: Session + HasPermission<AuthPermission> + Manager<R>, R: Role,
    {
        type Request = Request;
        type In = worker::Any;
        type Out = worker::Any;

        fn prepare(&mut self, session: &mut T, request: Self::Request) -> worker::Result<Shortcut> {
            permission_required!(session, AuthPermission::CanAuth);
            if session.set_role(&request.login, &request.password)? {
                Ok(Shortcut::Done)
            } else {
                Ok(Shortcut::Reject("wrong credentials".into()))
            }
        }
    }
}

mod change_password {
    use super::*;

    pub fn action<T, R>() -> service::Action<T>
        where T: Session + HasPermission<AuthPermission> + Manager<R>, R: Role,
    {
        let worker = Worker {
            _role: PhantomData,
        };
        service::Action::from_worker(worker)
    }

    struct Worker<R> {
        _role: PhantomData<R>,
    }

    #[derive(Deserialize)]
    struct Request {
        password: String,
    }

    impl<T, R> worker::Worker<T> for Worker<R>
        where T: Session + HasPermission<AuthPermission> + Manager<R>, R: Role,
    {
        type Request = Request;
        type In = worker::Any;
        type Out = worker::Any;

        fn prepare(&mut self, session: &mut T, request: Self::Request) -> worker::Result<Shortcut> {
            permission_required!(session, AuthPermission::CanChange);
            session.attach_password(&request.password)?;
            Ok(Shortcut::Done)
        }
    }
}
