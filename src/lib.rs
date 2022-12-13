use argon2::Argon2;
use jsonwebtoken_google::ParserError;
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct Authenticator<T, S: PasswordStorage<T>> {
    // Login & Register
    salt: SaltString,
    password_storage: S,
    argon2: Argon2<'static>,

    google_jwt_parser: Option<jsonwebtoken_google::Parser>,

    _phantom: std::marker::PhantomData<T>,
}

pub trait PasswordStorage<T> {
    fn get_password_hash(&self, user: &T) -> Option<String>;
    fn set_password_hash(&mut self, user: T, password_hash: impl ToString);
}

impl<T, S: PasswordStorage<T>> Authenticator<T, S> {
    /// Probably don't want to use this, since it can't infer the T and S properly.
    /// Use `AuthenticatorBuilder::default` instead.
    pub fn builder() -> AuthenticatorBuilder {
        AuthenticatorBuilder::default()
    }

    fn from_builder(builder: AuthenticatorBuilder, password_storage: S) -> Self {
        Self {
            salt: builder
                .salt
                .unwrap_or_else(|| SaltString::generate(&mut OsRng)),
            password_storage,
            argon2: Argon2::default(),

            google_jwt_parser: builder
                .google_client_id
                .map(|s| jsonwebtoken_google::Parser::new(&s)),

            _phantom: std::marker::PhantomData,
        }
    }

    pub fn register(&mut self, user: T, password: impl AsRef<[u8]>) -> Result<(), RegisterError> {
        let password_hash = self
            .argon2
            .hash_password(password.as_ref(), &self.salt)
            .unwrap()
            .serialize();
        self.password_storage
            .set_password_hash(user, password_hash.as_str());
        Ok(())
    }

    pub fn login(&mut self, user: T, password: impl AsRef<[u8]>) -> Result<(), LoginError> {
        let password_hash = self
            .password_storage
            .get_password_hash(&user)
            .ok_or(LoginError::UserNotFound)?;
        let password_hash = PasswordHash::new(&password_hash).unwrap();
        self.argon2
            .verify_password(password.as_ref(), &password_hash)
            .map_err(|_| LoginError::InvalidPassword)?;
        Ok(())
    }

    /// `AuthenticatorBuilder::with_google_client_id` must be called for google login support.
    /// Expects a google jwt token that was obtained with the same google client id
    /// as the one used to create the Authenticator.
    pub async fn login_with_google(
        &mut self,
        token: impl AsRef<str>,
    ) -> Result<GoogleTokenClaims, ParserError> {
        self.google_jwt_parser
            .as_ref()
            .expect("Call AuthenticatorBuilder::with_google_client_id for google login support")
            .parse(token.as_ref())
            .await
    }

    pub fn serialize(&self)
    where
        T: serde::Serialize,
    {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleTokenClaims {
    pub email: String,
    pub aud: String,
    pub iss: String,
    pub exp: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum RegisterError {
    NotAnEmail,
}

#[derive(Debug, Clone, Copy)]
pub enum LoginError {
    InvalidPassword,
    UserNotFound,
}

#[derive(Default)]
pub struct AuthenticatorBuilder {
    salt: Option<SaltString>,
    google_client_id: Option<String>,
}

impl AuthenticatorBuilder {
    pub fn with_salt(mut self, salt: impl AsRef<str>) -> Self {
        self.salt = Some(SaltString::new(salt.as_ref()).unwrap());
        self
    }

    pub fn with_google_client_id(mut self, google_client_id: impl ToString) -> Self {
        self.google_client_id = Some(google_client_id.to_string());
        self
    }

    pub fn finish<T, S: PasswordStorage<T>>(self, password_storage: S) -> Authenticator<T, S> {
        Authenticator::from_builder(self, password_storage)
    }
}

// Password Storage impls
impl<T> PasswordStorage<T> for HashMap<T, String>
where
    T: std::cmp::Eq + std::hash::Hash,
{
    fn get_password_hash(&self, user: &T) -> Option<String> {
        self.get(user).cloned()
    }

    fn set_password_hash(&mut self, user: T, password_hash: impl ToString) {
        self.insert(user, password_hash.to_string());
    }
}

#[cfg(feature = "redb")]
use redb::{Database, ReadableTable, TableDefinition};
#[cfg(feature = "redb")]
impl<T> PasswordStorage<T> for (Database, TableDefinition<'static, [u8], str>)
where
    T: AsRef<[u8]>,
{
    fn get_password_hash(&self, user: &T) -> Option<String> {
        let (db, table) = self;
        let read_txn = db.begin_read().unwrap();
        let table = read_txn.open_table(*table).unwrap();
        table.get(user.as_ref()).unwrap().map(|s| s.to_owned())
    }

    fn set_password_hash(&mut self, user: T, password_hash: impl ToString) {
        let (db, table) = self;
        let write_txn = db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(*table).unwrap();
            table
                .insert(user.as_ref(), &password_hash.to_string())
                .unwrap();
        }
        write_txn.commit().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::AuthenticatorBuilder;
    use redb::{Database, TableDefinition};
    use std::collections::HashMap;

    const TABLE: TableDefinition<[u8], str> = TableDefinition::new("my_data");

    #[test]
    fn test_hashmap() {
        let mut authenticator = AuthenticatorBuilder::default().finish(HashMap::new());
        authenticator.register("user", "password");
        assert!(authenticator.login("user", "password").is_ok());
    }

    #[test]
    fn test_redb() {
        let db = unsafe { Database::create("test.db").unwrap() };
        let mut authenticator = AuthenticatorBuilder::default().finish((db, TABLE));
        authenticator.register("user", "password");
        assert!(authenticator.login("user", "password").is_ok());
    }
}
