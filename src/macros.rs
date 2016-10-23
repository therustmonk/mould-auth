
#[macro_export]
macro_rules! permission_required {
    ($session:ident, $permission:path) => {
        if !$session.has_permission(&$permission) {
            return Err(::std::convert::From::from("You haven't permissions!"));
        }
    };
}
