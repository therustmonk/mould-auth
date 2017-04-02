use mould::prelude::*;
use permission::HasPermission;

pub trait Manager {
    fn set_role(&mut self, login: &str, password: &str) -> Result<(), &str>;
    fn attach_password(&mut self, password: &str) -> Result<(), &str>;
}

pub enum AuthPermission {
    CanAuth,
    CanChange,
}

/// A handler which use `CredentialManager` to set role to session.
/// The following actions available:
/// * `do-auth` - try to authorize by credential
pub struct AuthService { }

impl AuthService {
    pub fn new() -> Self {
        AuthService { }
    }
}

impl<T> Service<T> for AuthService
    where T: HasPermission<AuthPermission> + Manager {

    fn route(&self, request: &Request) -> Box<Worker<T>> {
        if request.action == "do-login" {
            Box::new(AuthCheckWorker::new())
        } else if request.action == "change-password" {
            Box::new(ChangePasswordWorker::new())
        } else {
            let msg = format!("Unknown action '{}' for auth service!", request.action);
            Box::new(RejectWorker::new(msg))
        }
    }
}

struct AuthCheckWorker { }

impl AuthCheckWorker {
    fn new() -> Self {
        AuthCheckWorker { }
    }
}

impl<T> Worker<T> for AuthCheckWorker
    where T: HasPermission<AuthPermission> + Manager {
    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanAuth);
        let login: String = extract_field!(request, "login");
        let password: String = extract_field!(request, "password");
        session.set_role(&login, &password)?;
        Ok(Shortcut::Done)
    }
}

struct ChangePasswordWorker { }

impl ChangePasswordWorker {
    fn new() -> Self {
        ChangePasswordWorker { }
    }
}

impl<T> Worker<T> for ChangePasswordWorker
    where T: HasPermission<AuthPermission> + Manager {

    fn prepare(&mut self, session: &mut T, mut request: Request) -> worker::Result<Shortcut> {
        permission_required!(session, AuthPermission::CanChange);
        let password: String = request.extract("password")?;
        session.attach_password(&password)?;
        Ok(Shortcut::Done)
    }
}

