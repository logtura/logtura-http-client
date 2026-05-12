//! Poll loop.
//!
//! Substitute `{cursor}` in URL/query, GET, extract rows via JSONPath,
//! emit each as a JSONL line on stdout, advance the cursor on the last
//! row. On 401: refresh + retry once. On repeated auth failure: exit
//! code 2 so Vector's exec source restarts us with fresh state.

use crate::auth::{self, TokenProvider};
use crate::config::Config;
use crate::cursor::Cursor;
use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use serde_json_path::JsonPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const EXIT_AUTH_FAILED: i32 = 2;

pub async fn run(cfg: Config) -> Result<()> {
    let client = Client::builder()
        .user_agent(concat!("logtura-http-client/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()
        .context("building HTTP client")?;
    let provider = auth::build(&cfg.auth)?;
    let mut cursor = Cursor::new(&cfg.cursor)?;
    let rows_path = JsonPath::parse(&cfg.rows.json_path)
        .map_err(|e| anyhow::anyhow!("invalid rows.json_path: {}", e))?;
    let method =
        reqwest::Method::from_bytes(cfg.method.as_bytes()).context("invalid http method")?;

    let interval = Duration::from_secs(cfg.scrape_interval_secs);
    let mut consecutive_auth_failures = 0u32;

    loop {
        match poll_once(&cfg, &client, &provider, &mut cursor, &rows_path, &method).await {
            Ok(emitted) => {
                consecutive_auth_failures = 0;
                tracing::debug!(emitted, "poll cycle done");
            }
            Err(PollError::Auth) => {
                consecutive_auth_failures += 1;
                tracing::error!(
                    attempts = consecutive_auth_failures,
                    "auth failed even after refresh; exiting so Vector restarts us"
                );
                std::process::exit(EXIT_AUTH_FAILED);
            }
            Err(PollError::Other(err)) => {
                tracing::warn!(error = %err, "poll cycle failed; backing off");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[derive(Debug)]
enum PollError {
    Auth,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for PollError {
    fn from(value: anyhow::Error) -> Self {
        PollError::Other(value)
    }
}

async fn poll_once(
    cfg: &Config,
    client: &Client,
    provider: &Arc<dyn TokenProvider>,
    cursor: &mut Cursor,
    rows_path: &JsonPath,
    method: &reqwest::Method,
) -> std::result::Result<usize, PollError> {
    let mut token = provider.current(client).await?;
    let response = send(cfg, client, &token, cursor, method).await?;

    let final_response = if response.status() == StatusCode::UNAUTHORIZED {
        tracing::info!("got 401; refreshing token and retrying once");
        token = provider
            .force_refresh(client)
            .await
            .map_err(|_| PollError::Auth)?;
        let retry = send(cfg, client, &token, cursor, method).await?;
        if retry.status() == StatusCode::UNAUTHORIZED {
            return Err(PollError::Auth);
        }
        retry
    } else {
        response
    };

    let status = final_response.status();
    let text = final_response
        .text()
        .await
        .context("reading response body")?;
    if !status.is_success() {
        return Err(PollError::Other(anyhow::anyhow!(
            "endpoint returned HTTP {}: {}",
            status,
            snip(&text, 200)
        )));
    }
    let body: Value = serde_json::from_str(&text).context("parsing response JSON")?;

    let nodes = rows_path.query(&body);
    let rows = if let Some(first) = nodes.first() {
        match first {
            Value::Array(arr) => arr.as_slice(),
            single => std::slice::from_ref(single),
        }
    } else {
        return Ok(0);
    };

    let mut stdout = tokio::io::stdout();
    let mut emitted = 0usize;
    for row in rows {
        let line = serde_json::to_string(row).context("serializing row")?;
        stdout
            .write_all(line.as_bytes())
            .await
            .context("writing to stdout")?;
        stdout.write_all(b"\n").await.context("writing newline")?;
        emitted += 1;
    }
    stdout.flush().await.context("flushing stdout")?;

    cursor.advance(&body);
    Ok(emitted)
}

async fn send(
    cfg: &Config,
    client: &Client,
    token: &str,
    cursor: &Cursor,
    method: &reqwest::Method,
) -> Result<reqwest::Response> {
    let url = cursor.substitute(&cfg.endpoint);
    let mut req = client.request(method.clone(), url);
    req = req.header("authorization", format!("Bearer {}", token));
    for (k, v) in &cfg.headers {
        req = req.header(k, cursor.substitute(v));
    }
    if !cfg.query.is_empty() {
        let q: Vec<(String, String)> = cfg
            .query
            .iter()
            .map(|(k, v)| (k.clone(), cursor.substitute(v)))
            .collect();
        req = req.query(&q);
    }
    req.send().await.context("sending HTTP request")
}

fn snip(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}
