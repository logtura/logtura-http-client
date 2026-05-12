//! Cursor templating for incremental polling.
//!
//! The configured `endpoint` URL and `query` values can contain
//! `{cursor}` placeholders. Before each request we substitute the
//! current cursor value; after each successful response we extract
//! the next cursor from the body via JSONPath.
//!
//! Cursor types we understand:
//! - ISO 8601 strings ("2026-05-12T00:00:00Z")
//! - Unix milliseconds ("1747000000000")
//! - Anything else passes through unchanged
//!
//! For the init value we parse a small DSL: `now`, `now - 90s`,
//! `now - 5m`, `now - 1h`. Anything that doesn't match the DSL is
//! used as-is.

use crate::config::CursorConfig;
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::Value;
use serde_json_path::JsonPath;

pub struct Cursor {
    current: String,
    json_path: Option<JsonPath>,
}

impl Cursor {
    pub fn new(cfg: &CursorConfig) -> Result<Self> {
        let json_path = match &cfg.json_path {
            Some(p) => {
                Some(JsonPath::parse(p).map_err(|e| anyhow!("invalid cursor.json_path: {}", e))?)
            }
            None => None,
        };
        let current = match &cfg.init {
            Some(s) => resolve_init(s)?,
            None => default_init(),
        };
        Ok(Self { current, json_path })
    }

    #[cfg(test)]
    pub fn current(&self) -> &str {
        &self.current
    }

    /// Substitute every `{cursor}` token in `s` with the current cursor.
    pub fn substitute(&self, s: &str) -> String {
        s.replace("{cursor}", &self.current)
    }

    /// Extract a new cursor from the response body. Silent no-op when
    /// no json_path is configured, or when the path matched nothing
    /// (e.g. empty result page — we keep the previous cursor).
    pub fn advance(&mut self, body: &Value) {
        let Some(jp) = &self.json_path else { return };
        let nodes = jp.query(body);
        if let Some(v) = nodes.first() {
            if let Some(s) = node_to_cursor_string(v) {
                self.current = s;
            }
        }
    }
}

fn node_to_cursor_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn default_init() -> String {
    // 90 seconds back from now is enough overlap that downstream
    // dedup handles the boundary cleanly; small enough that a
    // restart isn't expensive.
    relative_iso(-90)
}

fn resolve_init(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed == "now" {
        return Ok(Utc::now().to_rfc3339());
    }
    if let Some(rest) = trimmed
        .strip_prefix("now - ")
        .or_else(|| trimmed.strip_prefix("now-"))
    {
        let rest = rest.trim();
        let (num, unit) = rest.split_at(rest.len().saturating_sub(1));
        let n: i64 = num
            .trim()
            .parse()
            .map_err(|_| anyhow!("invalid cursor.init duration: {}", input))?;
        let secs = match unit {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            _ => return Err(anyhow!("invalid cursor.init unit (need s/m/h): {}", input)),
        };
        return Ok(relative_iso(-secs));
    }
    // Pass through — endpoint understands raw strings.
    Ok(trimmed.to_string())
}

fn relative_iso(secs: i64) -> String {
    let dt = Utc::now() + chrono::Duration::seconds(secs);
    dt.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn substitutes_cursor() {
        let c = Cursor::new(&CursorConfig {
            json_path: None,
            init: Some("X".into()),
        })
        .unwrap();
        assert_eq!(c.substitute("a {cursor} b"), "a X b");
    }

    #[test]
    fn advance_pulls_last_timestamp() {
        let mut c = Cursor::new(&CursorConfig {
            json_path: Some("$.result[-1].ts".into()),
            init: Some("1".into()),
        })
        .unwrap();
        let body = json!({"result": [{"ts": "10"}, {"ts": "20"}, {"ts": "30"}]});
        c.advance(&body);
        assert_eq!(c.current(), "30");
    }

    #[test]
    fn empty_result_keeps_cursor() {
        let mut c = Cursor::new(&CursorConfig {
            json_path: Some("$.result[-1].ts".into()),
            init: Some("X".into()),
        })
        .unwrap();
        c.advance(&json!({"result": []}));
        assert_eq!(c.current(), "X");
    }

    #[test]
    fn now_minus_seconds_parses() {
        let s = resolve_init("now - 90s").unwrap();
        // Parses as RFC 3339.
        chrono::DateTime::parse_from_rfc3339(&s).unwrap();
    }

    #[test]
    fn now_minus_minutes_parses() {
        let s = resolve_init("now - 5m").unwrap();
        chrono::DateTime::parse_from_rfc3339(&s).unwrap();
    }

    #[test]
    fn raw_strings_pass_through() {
        assert_eq!(resolve_init("1747000000000").unwrap(), "1747000000000");
    }
}
