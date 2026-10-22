//! Client authentication for the connections [`super::connect_nats`] opens.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;

/// How a connection opened by [`connect_nats`](super::connect_nats)
/// authenticates.
///
/// The fields combine the way the fields of a NATS `CONNECT` do, except that
/// `credentials` and `nkey` both answer the server's nonce, so only one of them
/// may be set. Files are read on every connect rather than once, so a rotated
/// credential is presented on the next reconnect without a restart.
#[derive(Clone, Default)]
pub struct NatsAuth {
    /// A NATS `.creds` file: a user JWT and the nkey seed that signs for it.
    pub credentials: Option<PathBuf>,
    /// A file holding an nkey seed, bare or in the decorated form `nsc` and
    /// `nk` write.
    pub nkey: Option<PathBuf>,
    /// Sent as `auth_token`.
    pub token: Option<String>,
    /// Sent as `user`.
    pub user: Option<String>,
    /// Sent as `pass`.
    pub password: Option<String>,
    /// Adjusts what the client presents after the fields above are applied.
    pub hook: Option<AuthHook>,
}

impl NatsAuth {
    fn is_empty(&self) -> bool {
        let Self {
            credentials,
            nkey,
            token,
            user,
            password,
            hook,
        } = self;
        credentials.is_none()
            && nkey.is_none()
            && token.is_none()
            && user.is_none()
            && password.is_none()
            && hook.is_none()
    }

    /// The options to build a connection on: plain ones when there is nothing
    /// to present, so an unauthenticated connection is unchanged.
    pub(super) fn connect_options(self) -> anyhow::Result<async_nats::ConnectOptions> {
        anyhow::ensure!(
            self.credentials.is_none() || self.nkey.is_none(),
            "a NATS connection takes a credentials file or an nkey seed, not both"
        );
        if self.is_empty() {
            return Ok(async_nats::ConnectOptions::new());
        }
        let auth = Arc::new(self);
        Ok(async_nats::ConnectOptions::with_auth_callback(
            move |nonce| {
                let auth = Arc::clone(&auth);
                async move {
                    auth.present(&nonce)
                        .await
                        .map_err(|e| async_nats::AuthError::new(format!("{e:#}")))
                }
            },
        ))
    }

    /// What to send in `CONNECT` for a server that issued `nonce`.
    pub(super) async fn present(&self, nonce: &[u8]) -> anyhow::Result<async_nats::Auth> {
        let mut auth = async_nats::Auth::new();
        if let Some(path) = &self.credentials {
            let contents = read(path, "credentials").await?;
            let (jwt, seed) = parse_credentials(&contents)
                .with_context(|| format!("invalid NATS credentials file {}", path.display()))?;
            let key = key_pair(seed)
                .with_context(|| format!("invalid nkey seed in {}", path.display()))?;
            auth.jwt = Some(jwt.to_string());
            auth.signature = Some(sign(&key, nonce)?);
        }
        if let Some(path) = &self.nkey {
            let contents = read(path, "nkey seed").await?;
            let seed = decorated_values(&contents)
                .into_iter()
                .find(|value| value.starts_with('S'))
                .unwrap_or_else(|| contents.trim());
            let key = key_pair(seed)
                .with_context(|| format!("invalid nkey seed in {}", path.display()))?;
            auth.nkey = Some(key.public_key());
            auth.signature = Some(sign(&key, nonce)?);
        }
        auth.token = self.token.clone();
        auth.username = self.user.clone();
        auth.password = self.password.clone();
        if let Some(hook) = &self.hook {
            (hook.0)(&mut auth)?;
        }
        Ok(auth)
    }
}

impl std::fmt::Debug for NatsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("NatsAuth")
            .field("credentials", &self.credentials)
            .field("nkey", &self.nkey)
            .field("token", &redacted(&self.token))
            .field("user", &self.user)
            .field("password", &redacted(&self.password))
            .field("hook", &self.hook)
            .finish()
    }
}

/// Runs on every connect with the [`async_nats::Auth`] that [`NatsAuth`]'s
/// fields produced, and may change any of it before it is sent.
///
/// This is for a server that wants credentials in a shape the fields cannot
/// express. An auth callout behind a server without trusted operators never
/// sees the `jwt` a client sends, for example, so a deployment may agree to
/// have clients repeat it as their token:
///
/// ```
/// # use wash_runtime::washlet::AuthHook;
/// let hook = AuthHook::new(|auth| {
///     auth.token = auth.jwt.clone();
///     Ok(())
/// });
/// ```
///
/// An error refuses the connection attempt, and is reported as an
/// authentication failure.
#[derive(Clone)]
pub struct AuthHook(Arc<AuthCallback>);

type AuthCallback = dyn Fn(&mut async_nats::Auth) -> anyhow::Result<()> + Send + Sync;

impl AuthHook {
    pub fn new(
        hook: impl Fn(&mut async_nats::Auth) -> anyhow::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(hook))
    }
}

impl std::fmt::Debug for AuthHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthHook")
    }
}

async fn read(path: &Path, what: &str) -> anyhow::Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read NATS {what} file {}", path.display()))
}

fn key_pair(seed: &str) -> anyhow::Result<nkeys::KeyPair> {
    // nkeys' errors name the problem, never the seed.
    nkeys::KeyPair::from_seed(seed).map_err(anyhow::Error::new)
}

fn sign(key: &nkeys::KeyPair, nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    key.sign(nonce)
        .map_err(anyhow::Error::new)
        .context("failed to sign the NATS server nonce")
}

/// The user JWT and nkey seed of a `.creds` file, in the order the file holds
/// them.
fn parse_credentials(contents: &str) -> anyhow::Result<(&str, &str)> {
    let mut values = decorated_values(contents).into_iter();
    let jwt = values.next().context("no user JWT block")?;
    let seed = values.next().context("no nkey seed block")?;
    Ok((jwt, seed))
}

/// Each value framed by a pair of `-----BEGIN …-----` / `------END …------`
/// lines, the way NATS tools decorate JWTs and seeds.
fn decorated_values(contents: &str) -> Vec<&str> {
    let is_marker = |line: &str| line.len() > 6 && line.starts_with("---") && line.ends_with("---");
    let lines: Vec<&str> = contents.lines().map(str::trim).collect();
    lines
        .windows(3)
        .filter_map(|window| match window {
            [start, value, end]
                if is_marker(start) && !value.is_empty() && !is_marker(value) && is_marker(end) =>
            {
                Some(*value)
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn creds_file(jwt: &str, seed: &str) -> String {
        format!(
            "-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n\
             ************************* IMPORTANT *************************\n\
             NKEY Seed printed below can be used to sign and prove identity.\n\n\
             -----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n\n\
             *************************************************************\n"
        )
    }

    #[test]
    fn credentials_parse_in_file_order() -> anyhow::Result<()> {
        let seed = nkeys::KeyPair::new_user().seed()?;
        let contents = creds_file("eyJhbGciOi.payload.sig", &seed);
        assert_eq!(
            parse_credentials(&contents)?,
            ("eyJhbGciOi.payload.sig", seed.as_str())
        );
        assert!(parse_credentials("eyJhbGciOi.payload.sig\n").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn the_seed_signs_the_nonce_and_the_hook_runs_last() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let key = nkeys::KeyPair::new_user();
        let path = dir.path().join("user.creds");
        std::fs::write(&path, creds_file("the.user.jwt", &key.seed()?))?;
        let auth = NatsAuth {
            credentials: Some(path),
            token: Some("ignored".into()),
            hook: Some(AuthHook::new(|auth| {
                auth.token = auth.jwt.clone();
                Ok(())
            })),
            ..Default::default()
        };

        let presented = auth.present(b"nonce").await?;
        assert_eq!(presented.jwt.as_deref(), Some("the.user.jwt"));
        assert_eq!(presented.token.as_deref(), Some("the.user.jwt"));
        key.verify(b"nonce", presented.signature.as_deref().unwrap_or_default())?;
        Ok(())
    }

    #[tokio::test]
    async fn an_nkey_file_may_be_bare_or_decorated() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let key = nkeys::KeyPair::new_user();
        let seed = key.seed()?;
        for (name, contents) in [
            ("bare.nk", format!("{seed}\n")),
            (
                "decorated.nk",
                format!("-----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"),
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, contents)?;
            let auth = NatsAuth {
                nkey: Some(path),
                ..Default::default()
            };
            let presented = auth.present(b"nonce").await?;
            assert_eq!(presented.nkey, Some(key.public_key()), "{name}");
            key.verify(b"nonce", presented.signature.as_deref().unwrap_or_default())?;
        }
        Ok(())
    }

    #[test]
    fn credentials_and_an_nkey_are_refused_together() {
        let auth = NatsAuth {
            credentials: Some("a.creds".into()),
            nkey: Some("a.nk".into()),
            ..Default::default()
        };
        assert!(auth.connect_options().is_err());
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let auth = NatsAuth {
            token: Some("s3cr3t-token".into()),
            user: Some("derek".into()),
            password: Some("s3cr3t-pass".into()),
            ..Default::default()
        };
        let debug = format!("{auth:?}");
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(debug.contains("derek"), "{debug}");
    }
}
