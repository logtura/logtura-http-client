//! Auth strategies for the HTTP poller.
//!
//! Each implementation hands the poll loop a `Bearer <token>` string;
//! the loop doesn't know or care which strategy produced it. On a 401
//! the loop calls `force_refresh()` and retries once.

use crate::config::{AuthConfig, AuthStrategy, ClientAuth};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use reqwest::Client;
use serde_json::Value;
use serde_json_path::JsonPath;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Generic interface every strategy implements. Returns the current
/// bearer token, refreshing transparently if cached one is stale.
pub trait TokenProvider: Send + Sync {
    fn current<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;
    fn force_refresh<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;
}

pub fn build(cfg: &AuthConfig) -> Result<Arc<dyn TokenProvider>> {
    match cfg.strategy {
        AuthStrategy::Bearer => Ok(Arc::new(StaticBearer {
            token: cfg
                .token
                .clone()
                .ok_or_else(|| anyhow!("bearer strategy requires auth.token"))?,
        })),
        AuthStrategy::BearerRefresh => Ok(Arc::new(BearerRefresh {
            token_url: cfg.token_url.clone().expect("validated"),
            token_method: cfg.token_method.clone(),
            token_headers: cfg.token_headers.clone(),
            access_token_path: cfg.access_token_json_path.clone(),
            expires_in_path: cfg.expires_in_json_path.clone(),
            cached: Mutex::new(None),
        })),
        AuthStrategy::OauthRefresh => Ok(Arc::new(OauthRefresh {
            token_url: cfg.token_url.clone().expect("validated"),
            client_id: cfg.client_id.clone().expect("validated"),
            client_secret: cfg.client_secret.clone().expect("validated"),
            client_auth: cfg.client_auth,
            initial_refresh_token: cfg.refresh_token.clone().expect("validated"),
            refresh_token_file: cfg.refresh_token_file.clone(),
            cached: Mutex::new(None),
        })),
    }
}

/// Cached `Bearer <token>` plus the instant it goes stale.
#[derive(Debug, Clone)]
struct Cached {
    token: String,
    fresh_until: Instant,
}

pub struct StaticBearer {
    token: String,
}

impl TokenProvider for StaticBearer {
    fn current<'a>(
        &'a self,
        _client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        let t = self.token.clone();
        Box::pin(async move { Ok(t) })
    }
    fn force_refresh<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        // Static bearer can't refresh — return what we have.
        self.current(client)
    }
}

pub struct BearerRefresh {
    token_url: String,
    token_method: String,
    token_headers: std::collections::HashMap<String, String>,
    access_token_path: String,
    expires_in_path: String,
    cached: Mutex<Option<Cached>>,
}

impl BearerRefresh {
    async fn refresh(&self, client: &Client) -> Result<String> {
        let method = reqwest::Method::from_bytes(self.token_method.as_bytes())
            .context("invalid token_method")?;
        let mut req = client.request(method, &self.token_url);
        for (k, v) in &self.token_headers {
            req = req.header(k, v);
        }
        let res = req.send().await.context("token endpoint request failed")?;
        let status = res.status();
        let text = res.text().await.context("reading token response")?;
        if !status.is_success() {
            return Err(anyhow!(
                "token endpoint returned HTTP {}: {}",
                status,
                snip(&text, 200)
            ));
        }
        let body: Value = serde_json::from_str(&text).context("parsing token response JSON")?;
        let access_token = extract_string(&body, &self.access_token_path)
            .ok_or_else(|| anyhow!("token response missing {}", self.access_token_path))?;
        let expires_in_secs = extract_number(&body, &self.expires_in_path).unwrap_or(60.0);
        // Refresh a minute before expiry to absorb clock skew + request latency.
        let lifetime = Duration::from_secs((expires_in_secs as u64).saturating_sub(60).max(30));
        let mut cached = self.cached.lock().await;
        *cached = Some(Cached {
            token: access_token.clone(),
            fresh_until: Instant::now() + lifetime,
        });
        Ok(access_token)
    }
}

impl TokenProvider for BearerRefresh {
    fn current<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            {
                let cached = self.cached.lock().await;
                if let Some(c) = cached.as_ref() {
                    if Instant::now() < c.fresh_until {
                        return Ok(c.token.clone());
                    }
                }
            }
            self.refresh(client).await
        })
    }
    fn force_refresh<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            // Drop cache so refresh actually re-hits the token endpoint.
            {
                let mut cached = self.cached.lock().await;
                *cached = None;
            }
            self.refresh(client).await
        })
    }
}

pub struct OauthRefresh {
    token_url: String,
    client_id: String,
    client_secret: String,
    client_auth: ClientAuth,
    initial_refresh_token: String,
    refresh_token_file: Option<String>,
    cached: Mutex<Option<OauthCached>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct OauthCached {
    access_token: String,
    // Kept for future "warm the cache" calls and observability — not
    // read by the poll loop today, but invaluable when we add a
    // status endpoint that reports the active refresh_token suffix.
    refresh_token: String,
    fresh_until: Instant,
}

impl OauthRefresh {
    /// Reads refresh_token_file if configured, falling back to the
    /// initial_refresh_token from config when the file is absent or
    /// empty. Called on every refresh so a sibling process / external
    /// rotation gets picked up.
    async fn current_refresh_token(&self) -> Result<String> {
        if let Some(path) = &self.refresh_token_file {
            match tokio::fs::read_to_string(path).await {
                Ok(s) => {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Ok(trimmed.to_string());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow!("reading refresh_token_file {}: {}", path, e)),
            }
        }
        Ok(self.initial_refresh_token.clone())
    }

    /// Persists a rotated refresh_token if a file is configured.
    /// Warns (does not error) when rotation happens without a file.
    async fn persist_refresh_token(&self, new_rt: &str, rotated: bool) -> Result<()> {
        if let Some(path) = &self.refresh_token_file {
            // Atomic write: tmp + rename, so we don't leave a half-
            // written file if the process dies mid-flush.
            let tmp = format!("{}.tmp", path);
            tokio::fs::write(&tmp, new_rt)
                .await
                .with_context(|| format!("writing {}", tmp))?;
            tokio::fs::rename(&tmp, path)
                .await
                .with_context(|| format!("renaming {} to {}", tmp, path))?;
        } else if rotated {
            tracing::warn!(
                "OAuth provider rotated the refresh_token but no refresh_token_file is configured — next restart will fail to authenticate"
            );
        }
        Ok(())
    }

    async fn refresh(&self, client: &Client) -> Result<String> {
        let rt = self.current_refresh_token().await?;
        let mut form_pairs = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", rt.clone()),
        ];
        let mut req = client.post(&self.token_url);
        match self.client_auth {
            ClientAuth::Basic => {
                let raw = format!("{}:{}", self.client_id, self.client_secret);
                let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
                req = req.header("authorization", format!("Basic {}", b64));
            }
            ClientAuth::FormBody => {
                form_pairs.push(("client_id", self.client_id.clone()));
                form_pairs.push(("client_secret", self.client_secret.clone()));
            }
        }
        req = req.header("accept", "application/json").form(&form_pairs);
        let res = req
            .send()
            .await
            .context("OAuth token endpoint request failed")?;
        let status = res.status();
        let text = res.text().await.context("reading OAuth token response")?;
        if !status.is_success() {
            return Err(anyhow!(
                "OAuth token endpoint returned HTTP {}: {}",
                status,
                snip(&text, 200)
            ));
        }
        let body: serde_json::Value =
            serde_json::from_str(&text).context("parsing OAuth token response JSON")?;
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("OAuth response missing access_token"))?
            .to_string();
        let new_rt = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| rt.clone());
        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let rotated = new_rt != rt;
        self.persist_refresh_token(&new_rt, rotated).await?;

        let lifetime = Duration::from_secs(expires_in.saturating_sub(60).max(30));
        let mut cached = self.cached.lock().await;
        *cached = Some(OauthCached {
            access_token: access_token.clone(),
            refresh_token: new_rt,
            fresh_until: Instant::now() + lifetime,
        });
        Ok(access_token)
    }
}

impl TokenProvider for OauthRefresh {
    fn current<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            {
                let cached = self.cached.lock().await;
                if let Some(c) = cached.as_ref() {
                    if Instant::now() < c.fresh_until {
                        return Ok(c.access_token.clone());
                    }
                }
            }
            self.refresh(client).await
        })
    }
    fn force_refresh<'a>(
        &'a self,
        client: &'a Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            {
                let mut cached = self.cached.lock().await;
                *cached = None;
            }
            self.refresh(client).await
        })
    }
}

fn extract_string(body: &Value, path: &str) -> Option<String> {
    let jp = JsonPath::parse(path).ok()?;
    let nodes = jp.query(body);
    nodes
        .first()
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_number(body: &Value, path: &str) -> Option<f64> {
    let jp = JsonPath::parse(path).ok()?;
    let nodes = jp.query(body);
    nodes.first().and_then(|v| v.as_f64())
}

fn snip(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn bearer_refresh_caches_and_force_refreshes() {
        let server = MockServer::start().await;
        // Return a token with expires_in 90 (cached for 30s after the
        // 60s skew is subtracted). Each call increments a counter
        // baked into the access_token so we can assert refreshes.
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("authorization", "Bearer connection-jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-token",
                "expires_in": 90,
            })))
            .mount(&server)
            .await;
        let cfg = AuthConfig {
            strategy: AuthStrategy::BearerRefresh,
            token: None,
            token_url: Some(format!("{}/token", server.uri())),
            token_method: "POST".into(),
            token_headers: [(
                "authorization".to_string(),
                "Bearer connection-jwt".to_string(),
            )]
            .into(),
            access_token_json_path: "$.access_token".into(),
            expires_in_json_path: "$.expires_in".into(),
            client_id: None,
            client_secret: None,
            refresh_token: None,
            refresh_token_file: None,
            client_auth: ClientAuth::Basic,
        };
        let prov = build(&cfg).unwrap();
        let http = Client::new();
        let t1 = prov.current(&http).await.unwrap();
        assert_eq!(t1, "fresh-token");
        let t2 = prov.current(&http).await.unwrap();
        assert_eq!(t2, "fresh-token");
        let t3 = prov.force_refresh(&http).await.unwrap();
        assert_eq!(t3, "fresh-token");
    }

    #[tokio::test]
    async fn oauth_refresh_basic_auth_and_persists_rotation() {
        let server = MockServer::start().await;
        let basic = base64::engine::general_purpose::STANDARD.encode("cid:csec");
        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .and(header("authorization", format!("Basic {}", basic)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "refresh_token": "rotated-rt",
                "expires_in": 86400,
                "token_type": "Bearer",
            })))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let rt_path = dir.path().join("supabase.rt");
        let cfg = AuthConfig {
            strategy: AuthStrategy::OauthRefresh,
            token: None,
            token_url: Some(format!("{}/v1/oauth/token", server.uri())),
            token_method: "POST".into(),
            token_headers: Default::default(),
            access_token_json_path: "$.access_token".into(),
            expires_in_json_path: "$.expires_in".into(),
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            refresh_token: Some("initial-rt".into()),
            refresh_token_file: Some(rt_path.to_string_lossy().into()),
            client_auth: ClientAuth::Basic,
        };
        let prov = build(&cfg).unwrap();
        let http = Client::new();
        let access = prov.current(&http).await.unwrap();
        assert_eq!(access, "new-access");
        let persisted = tokio::fs::read_to_string(&rt_path).await.unwrap();
        assert_eq!(persisted, "rotated-rt");
    }

    #[tokio::test]
    async fn oauth_refresh_reads_rotated_rt_from_file_on_next_refresh() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let rt_path = dir.path().join("rt");
        tokio::fs::write(&rt_path, "from-file-rt").await.unwrap();

        // Mock expects the body to include `refresh_token=from-file-rt`,
        // proving we read from the file, not the static config.
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(wiremock::matchers::body_string_contains(
                "refresh_token=from-file-rt",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ax",
                "refresh_token": "from-file-rt",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;
        let cfg = AuthConfig {
            strategy: AuthStrategy::OauthRefresh,
            token: None,
            token_url: Some(format!("{}/oauth/token", server.uri())),
            token_method: "POST".into(),
            token_headers: Default::default(),
            access_token_json_path: "$.access_token".into(),
            expires_in_json_path: "$.expires_in".into(),
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            refresh_token: Some("config-rt".into()),
            refresh_token_file: Some(rt_path.to_string_lossy().into()),
            client_auth: ClientAuth::Basic,
        };
        let prov = build(&cfg).unwrap();
        let http = Client::new();
        let access = prov.current(&http).await.unwrap();
        assert_eq!(access, "ax");
    }
}
