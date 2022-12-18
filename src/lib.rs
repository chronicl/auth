use argon2::Argon2;
pub use jsonwebtoken_google::ParserError as GoogleError;
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible};

pub struct Authenticator<T, S: PasswordStorage<T>> {
    // Login & Register
    salt: SaltString,
    password_storage: S,
    argon2: Argon2<'static>,

    google_jwt_parser: Option<jsonwebtoken_google::Parser>,

    _phantom: std::marker::PhantomData<T>,
}

pub trait PasswordStorage<T> {
    type Error: std::error::Error;
    fn get_password_hash(&self, user: &T) -> Result<Option<String>, Self::Error>;
    fn set_password_hash(
        &mut self,
        user: T,
        password_hash: impl ToString,
    ) -> Result<(), Self::Error>;
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

    pub fn register(
        &mut self,
        user: T,
        password: impl AsRef<[u8]>,
    ) -> Result<(), RegisterError<S::Error>> {
        let password_hash = self
            .argon2
            .hash_password(password.as_ref(), &self.salt)
            .map_err(|_| RegisterError::HashingError)?
            .serialize();
        self.password_storage
            .set_password_hash(user, password_hash.as_str())?;
        Ok(())
    }

    pub fn login(
        &mut self,
        user: &T,
        password: impl AsRef<[u8]>,
    ) -> Result<(), LoginError<S::Error>> {
        let password_hash = self
            .password_storage
            .get_password_hash(user)?
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
    ) -> Result<GoogleTokenClaims, GoogleError> {
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

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum RegisterError<E> {
    #[error("Email already in use")]
    NotAnEmail,
    #[error("Error hashing password")]
    HashingError,
    #[error("Storage error")]
    Storage(E),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum LoginError<E> {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("User not found")]
    UserNotFound,
    #[error("Storage error")]
    Storage(E),
}

impl<E> From<E> for RegisterError<E> {
    fn from(e: E) -> Self {
        Self::Storage(e)
    }
}

impl<E> From<E> for LoginError<E> {
    fn from(e: E) -> Self {
        Self::Storage(e)
    }
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
    type Error = Infallible;

    fn get_password_hash(&self, user: &T) -> Result<Option<String>, Self::Error> {
        Ok(self.get(user).cloned())
    }

    fn set_password_hash(
        &mut self,
        user: T,
        password_hash: impl ToString,
    ) -> Result<(), Self::Error> {
        self.insert(user, password_hash.to_string());
        Ok(())
    }
}

pub struct RedbStorage<K: Serialize> {
    db: Database,
    table: TableDefinition<'static, [u8], str>,
    _phantom: std::marker::PhantomData<K>,
}

impl<K: Serialize> RedbStorage<K> {
    /// Inserts a new table into the database. The table definition is
    /// TableDefinition<'static, [u8], str> with name "authenticator_redb_storage".
    pub fn new(db: Database) -> Self {
        let table = TableDefinition::new("authenticator_redb_storage");
        // Making sure the table exists
        {
            db.begin_write().unwrap().open_table(table).unwrap();
        }
        Self {
            db,
            table,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "redb")]
use redb::{Database, ReadableTable, TableDefinition};
#[cfg(feature = "redb")]
impl<T> PasswordStorage<T> for RedbStorage<T>
where
    T: Serialize,
{
    type Error = redb::Error;

    fn get_password_hash(&self, user: &T) -> Result<Option<String>, Self::Error> {
        let RedbStorage { db, table, .. } = self;
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(*table)?;
        Ok(table
            .get(&bincode::serialize(user).unwrap())
            .unwrap()
            .map(|s| s.to_owned()))
    }

    fn set_password_hash(
        &mut self,
        user: T,
        password_hash: impl ToString,
    ) -> Result<(), Self::Error> {
        let RedbStorage { db, table, .. } = self;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(*table)?;
            table.insert(
                &bincode::serialize(&user).unwrap(),
                &password_hash.to_string(),
            )?;
        }
        write_txn.commit().unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{AuthenticatorBuilder, RedbStorage};
    use redb::Database;
    use std::collections::HashMap;

    #[test]
    fn test_hashmap() {
        let mut authenticator = AuthenticatorBuilder::default().finish(HashMap::new());
        authenticator.register("user", "password").unwrap();
        assert!(authenticator.login(&"user", "password").is_ok());
    }

    #[test]
    fn test_redb() {
        let db = unsafe { Database::create("test.db").unwrap() };
        let mut authenticator = AuthenticatorBuilder::default().finish(RedbStorage::new(db));
        authenticator.register("user", "password").unwrap();
        assert!(authenticator.login(&"user", "password").is_ok());
    }
}
