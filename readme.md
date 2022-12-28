### Authenticator

An extremely simple authenticator that supports password authentication and oauth authentication via google.

Hashes of the passwords can be stored in any container that implements `PasswordStorage` - this crate contains impls for `HashMap`, `sled` and `redb` if their respective features `sled` or `redb` are enabled.

#### Example

```rust
let mut authenticator = AuthenticatorBuilder::default().finish(HashMap::new());
authenticator.register("user", "password");
assert!(authenticator.login("user", "password").is_ok());
```
