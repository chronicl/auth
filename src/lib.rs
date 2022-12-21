use argon2::Argon2;
pub use jsonwebtoken_google::ParserError as GoogleError;
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

pub struct Authenticator<T, S: PasswordStorage<T>> {
    // Login & Register
    salt: SaltString,
    password_storage: S,
    argon2: Argon2<'static>,

    google_jwt_parser: Option<jsonwebtoken_google::Parser>,

    _phantom: std::marker::PhantomData<T>,
}

pub trait PasswordStorage<T> {
    type Error: std::error::Error + 'static;
    fn get_password_hash(&self, user: &T) -> Result<Option<String>, Self::Error>;
    fn set_password_hash(&self, user: T, password_hash: impl ToString) -> Result<(), Self::Error>;
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
            .map_err(|_| RegisterError::HashingError)?
            .serialize();
        if self
            .password_storage
            .get_password_hash(&user)
            .map_err(RegisterError::other)?
            .is_some()
        {
            return Err(RegisterError::AlreadyExists);
        }
        self.password_storage
            .set_password_hash(user, password_hash.as_str())
            .map_err(RegisterError::other)?;
        Ok(())
    }

    pub fn login(&mut self, user: &T, password: impl AsRef<[u8]>) -> Result<(), LoginError> {
        let password_hash = self
            .password_storage
            .get_password_hash(user)
            .map_err(LoginError::other)?
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

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("User already exists")]
    AlreadyExists,
    #[error("Error hashing password")]
    HashingError,
    #[error("Other error")]
    Other(Box<dyn std::error::Error>),
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("Invalid password")]
    InvalidPassword,
    #[error("User not found")]
    UserNotFound,
    #[error("Other error")]
    Other(Box<dyn std::error::Error>),
}

impl LoginError {
    pub fn other<E>(e: E) -> Self
    where
        E: std::error::Error + 'static,
    {
        Self::Other(Box::new(e))
    }
}

impl RegisterError {
    pub fn other<E>(e: E) -> Self
    where
        E: std::error::Error + 'static,
    {
        Self::Other(Box::new(e))
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
impl<T> PasswordStorage<T> for Arc<Mutex<HashMap<T, String>>>
where
    T: std::cmp::Eq + std::hash::Hash,
{
    type Error = Infallible;

    fn get_password_hash(&self, user: &T) -> Result<Option<String>, Self::Error> {
        Ok(self.lock().unwrap().get(user).cloned())
    }

    fn set_password_hash(&self, user: T, password_hash: impl ToString) -> Result<(), Self::Error> {
        self.lock().unwrap().insert(user, password_hash.to_string());
        Ok(())
    }
}

#[cfg(feature = "redb")]
pub struct RedbStorage<K: Serialize> {
    db: Arc<Database>,
    table: TableDefinition<'static, [u8], str>,
    _phantom: std::marker::PhantomData<K>,
}

#[cfg(feature = "redb")]
pub use redb::Error as RedbError;

#[cfg(feature = "redb")]
impl<K: Serialize> RedbStorage<K> {
    /// Inserts a new table into the database. The table definition is
    /// TableDefinition<'static, [u8], str> with name "authenticator_redb_storage".
    pub fn new(db: Arc<Database>) -> Self {
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

    fn set_password_hash(&self, user: T, password_hash: impl ToString) -> Result<(), Self::Error> {
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
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[test]
    fn test_hashmap() {
        let mut authenticator =
            AuthenticatorBuilder::default().finish(Arc::new(Mutex::new(HashMap::new())));
        authenticator.register("user", "password").unwrap();
        assert!(authenticator.login(&"user", "password").is_ok());
    }

    #[test]
    fn test_redb() {
        let db = unsafe { Database::create("test.db").unwrap() };
        let mut authenticator =
            AuthenticatorBuilder::default().finish(RedbStorage::new(Arc::new(db)));
        authenticator.register("user", "password").unwrap();
        assert!(authenticator.login(&"user", "password").is_ok());
    }
}
