use std::error;
use std::fmt;
use std::collections::HashMap;
use super::*;

enum Rule<T: Role> {
    Once(Option<T>),
    Multiple(Box<Fn() -> Option<T> + Send>),
}

#[derive(Debug)]
pub enum Error {
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TockenChecker Error")
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "error of token checker"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub struct StringChecker<T: Role> {
    tokens: HashMap<String, Rule<T>>,
}

impl<T: Role> StringChecker<T> {
    pub fn new() -> Self {
        StringChecker {
            tokens: HashMap::new(),
        }
    }

    fn add_rule(&mut self, token: &str, rule: Rule<T>) {
        self.tokens.insert(token.to_owned(), rule);
    }

    pub fn add_once(&mut self, token: &str, role: T) {
        let rule = Rule::Once(Some(role));
        self.add_rule(token, rule);
    }
}

impl<T: Role + Clone + Send + 'static> StringChecker<T> {
    pub fn add_multiple(&mut self, token: &str, role: T) {
        let generator = move || Some(role.clone());
        let rule = Rule::Multiple(Box::new(generator));
        self.add_rule(token, rule);
    }
}

impl<T: Role> TokenManager<T> for StringChecker<T> {
    fn pick_role(&mut self, token: &str) -> Result<Option<T>> {
        let (result, remove) = match self.tokens.get_mut(token) {
            Some(&mut Rule::Multiple(ref generator)) => (generator(), false),
            Some(&mut Rule::Once(ref mut role)) => (role.take(), true),
            None => (None, false),
        };
        if remove {
            self.tokens.remove(token);
        }
        Ok(result)
    }

    fn acquire_token(&mut self, _: &Role) -> Result<String> {
        Err(Box::new(Error::Unsupported))
    }
}
