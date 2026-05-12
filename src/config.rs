//! TOML config parsing.
//!
//! Schema mirrors Vector's `http_client` source for forward
//! compatibility, plus two new auth strategies (`bearer_refresh`,
//! `oauth_refresh`) and explicit `[cursor]` / `[rows]` blocks for
//! incremental polling against time-windowed APIs.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_interval")]
    pub scrape_interval_secs: u64,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub query: HashMap<String, String>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub cursor: CursorConfig,
    #[serde(default)]
    pub rows: RowsConfig,
}

fn default_method() -> String {
    "GET".into()
}
fn default_interval() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub strategy: AuthStrategy,
    /// Static bearer token (strategy = "bearer").
    #[serde(default)]
    pub token: Option<String>,
    /// URL to POST for a fresh access_token (strategy = "bearer_refresh").
    #[serde(default)]
    pub token_url: Option<String>,
    /// HTTP method for the token URL. Default POST.
    #[serde(default = "default_token_method")]
    pub token_method: String,
    /// Headers sent to the token URL. Typically carries a Logtura
    /// connection-scoped JWT in `bearer_refresh`.
    #[serde(default)]
    pub token_headers: HashMap<String, String>,
    /// JSONPath into the token-URL response for the access_token.
    /// Defaults to `$.access_token` (RFC 6749).
    #[serde(default = "default_at_path")]
    pub access_token_json_path: String,
    /// JSONPath for the access_token's lifetime in seconds.
    /// Defaults to `$.expires_in`. If absent, we cache for 60s.
    #[serde(default = "default_exp_path")]
    pub expires_in_json_path: String,

    /// RFC 6749 client_id (strategy = "oauth_refresh").
    #[serde(default)]
    pub client_id: Option<String>,
    /// RFC 6749 client_secret (strategy = "oauth_refresh").
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Initial refresh_token (strategy = "oauth_refresh"). Read from
    /// `refresh_token_file` first when set; this value is the fallback.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Where to persist rotated refresh_tokens. Required for providers
    /// like Supabase that rotate on every refresh.
    #[serde(default)]
    pub refresh_token_file: Option<String>,
    /// How to authenticate against the OAuth token URL.
    /// `basic` (default) sends client_id/secret in the Basic header;
    /// `form_body` puts them in the body alongside the grant.
    #[serde(default = "default_client_auth")]
    pub client_auth: ClientAuth,
}

fn default_token_method() -> String {
    "POST".into()
}
fn default_at_path() -> String {
    "$.access_token".into()
}
fn default_exp_path() -> String {
    "$.expires_in".into()
}
fn default_client_auth() -> ClientAuth {
    ClientAuth::Basic
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrategy {
    Bearer,
    BearerRefresh,
    OauthRefresh,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    Basic,
    FormBody,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorConfig {
    /// JSONPath into the response body to extract the next cursor
    /// value from the last row. Typical: `$.result[-1].timestamp`.
    /// When empty, no cursor templating happens.
    #[serde(default)]
    pub json_path: Option<String>,
    /// Initial cursor value. Supports `now`, `now - <N>s|m|h`, or a
    /// raw string the endpoint understands (ISO 8601, unix ms, etc.).
    #[serde(default)]
    pub init: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowsConfig {
    /// JSONPath to the array of rows inside the response body. Default
    /// `$` (the whole body is the array). Each row is emitted as one
    /// JSONL line on stdout.
    #[serde(default = "default_rows_path")]
    pub json_path: String,
}

fn default_rows_path() -> String {
    "$".into()
}

pub fn load(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let interpolated = interpolate_env(&raw)?;
    let cfg: Config = toml::from_str(&interpolated).context("parsing TOML")?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Replace `${VAR}` (and `${VAR:-default}`) tokens with values from
/// process env. We do this BEFORE TOML parsing so secrets land in
/// string values without contaminating the schema. Same idea as
/// Vector's env interpolation.
fn interpolate_env(input: &str) -> Result<String> {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}").unwrap();
    let mut errors = Vec::new();
    let out = re.replace_all(input, |caps: &regex::Captures<'_>| {
        let name = &caps[1];
        match std::env::var(name) {
            Ok(v) => v,
            Err(_) => {
                if let Some(default) = caps.get(2) {
                    default.as_str().to_string()
                } else {
                    errors.push(name.to_string());
                    String::new()
                }
            }
        }
    });
    if !errors.is_empty() {
        return Err(anyhow!(
            "missing env vars referenced in config: {}",
            errors.join(", ")
        ));
    }
    Ok(out.into_owned())
}

fn validate(cfg: &Config) -> Result<()> {
    match cfg.auth.strategy {
        AuthStrategy::Bearer => {
            if cfg.auth.token.is_none() {
                return Err(anyhow!("auth.strategy = bearer requires auth.token"));
            }
        }
        AuthStrategy::BearerRefresh => {
            if cfg.auth.token_url.is_none() {
                return Err(anyhow!(
                    "auth.strategy = bearer_refresh requires auth.token_url"
                ));
            }
        }
        AuthStrategy::OauthRefresh => {
            if cfg.auth.token_url.is_none()
                || cfg.auth.client_id.is_none()
                || cfg.auth.client_secret.is_none()
                || cfg.auth.refresh_token.is_none()
            {
                return Err(anyhow!(
                    "auth.strategy = oauth_refresh requires token_url, client_id, client_secret, refresh_token"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer() {
        let toml = r#"
            endpoint = "https://example.com/logs"
            scrape_interval_secs = 15
            [auth]
            strategy = "bearer"
            token = "abc"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.auth.strategy, AuthStrategy::Bearer);
        assert_eq!(cfg.scrape_interval_secs, 15);
    }

    #[test]
    fn parses_bearer_refresh() {
        let toml = r#"
            endpoint = "https://example.com/logs"
            [auth]
            strategy = "bearer_refresh"
            token_url = "https://saas/api/token"
            [auth.token_headers]
            authorization = "Bearer xyz"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.auth.strategy, AuthStrategy::BearerRefresh);
        assert_eq!(cfg.auth.token_headers.len(), 1);
    }

    #[test]
    fn parses_oauth_refresh_with_rotation_file() {
        let toml = r#"
            endpoint = "https://example.com/logs"
            [auth]
            strategy = "oauth_refresh"
            token_url = "https://api.supabase.com/v1/oauth/token"
            client_id = "cid"
            client_secret = "csec"
            refresh_token = "rt"
            refresh_token_file = "/var/lib/x.rt"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.auth.strategy, AuthStrategy::OauthRefresh);
        assert_eq!(
            cfg.auth.refresh_token_file.as_deref(),
            Some("/var/lib/x.rt")
        );
    }

    #[test]
    fn bearer_without_token_fails() {
        let toml = r#"
            endpoint = "https://x"
            [auth]
            strategy = "bearer"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn env_interpolation_substitutes_and_errors_when_missing() {
        std::env::set_var("LOGTURA_TEST_TOKEN", "secret-1");
        let raw = r#"value = "${LOGTURA_TEST_TOKEN}""#;
        let out = interpolate_env(raw).unwrap();
        assert!(out.contains("secret-1"));

        // Missing var with no default is an error.
        let raw = r#"value = "${THIS_DOES_NOT_EXIST_QQQ}""#;
        assert!(interpolate_env(raw).is_err());

        // Missing with default falls back.
        let raw = r#"value = "${THIS_DOES_NOT_EXIST_QQQ:-fallback}""#;
        let out = interpolate_env(raw).unwrap();
        assert!(out.contains("fallback"));
    }
}
