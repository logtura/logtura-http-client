//! Integration tests for the poll loop's behavior end-to-end.
//!
//! Each test wires a fresh mock token server, a fresh mock log
//! endpoint, and drives `poll_once` once or twice with an in-memory
//! writer instead of stdout. Asserts cover cursor templating, JSONL
//! emission shape, cursor advancement, 401-retry, and the nested
//! Supabase analytics response shape.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use logtura_http_client_lib::auth::{self, TokenProvider};
use logtura_http_client_lib::config::{
    AuthConfig, AuthStrategy, ClientAuth, Config, CursorConfig, RowsConfig,
};
use logtura_http_client_lib::cursor::Cursor;
use logtura_http_client_lib::poll::{poll_once, PollError};
use reqwest::Client;
use serde_json_path::JsonPath;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Sets up a bearer_refresh token server backed by a wiremock instance.
/// The token endpoint returns a fixed `integration-bearer` access_token
/// with a 1h lifetime; tests that need to force a refresh shadow the
/// mock with a second responder.
async fn mock_token_server(token: &'static str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": token,
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;
    server
}

fn bearer_refresh_cfg(token_server: &MockServer) -> AuthConfig {
    AuthConfig {
        strategy: AuthStrategy::BearerRefresh,
        token: None,
        token_url: Some(format!("{}/token", token_server.uri())),
        token_method: "POST".into(),
        token_headers: HashMap::new(),
        access_token_json_path: "$.access_token".into(),
        expires_in_json_path: "$.expires_in".into(),
        client_id: None,
        client_secret: None,
        refresh_token: None,
        refresh_token_file: None,
        client_auth: ClientAuth::Basic,
    }
}

fn build_cfg(endpoint: String, rows_path: &str, cursor_path: Option<&str>) -> Config {
    Config {
        endpoint,
        method: "GET".into(),
        scrape_interval_secs: 30,
        headers: HashMap::new(),
        query: HashMap::new(),
        auth: AuthConfig {
            strategy: AuthStrategy::Bearer,
            token: Some("placeholder".into()),
            token_url: None,
            token_method: "POST".into(),
            token_headers: HashMap::new(),
            access_token_json_path: "$.access_token".into(),
            expires_in_json_path: "$.expires_in".into(),
            client_id: None,
            client_secret: None,
            refresh_token: None,
            refresh_token_file: None,
            client_auth: ClientAuth::Basic,
        },
        cursor: CursorConfig {
            json_path: cursor_path.map(|s| s.into()),
            init: Some("X-INIT".into()),
        },
        rows: RowsConfig {
            json_path: rows_path.into(),
        },
    }
}

fn client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn emits_one_jsonl_per_row_and_advances_cursor() {
    let logs = MockServer::start().await;
    let token = mock_token_server("bearer-A").await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(query_param("since", "X-INIT"))
        .and(header("authorization", "Bearer bearer-A"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [
                {"id": 1, "ts": "T-100", "msg": "first"},
                {"id": 2, "ts": "T-200", "msg": "second"},
                {"id": 3, "ts": "T-300", "msg": "third"},
            ]
        })))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(
        format!("{}/logs", logs.uri()),
        "$.events",
        Some("$.events[-1].ts"),
    );
    cfg.query.insert("since".into(), "{cursor}".into());
    cfg.auth = bearer_refresh_cfg(&token);

    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let emitted = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await
    .expect("poll");
    assert_eq!(emitted, 3);

    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.trim_end().split('\n').collect();
    assert_eq!(lines.len(), 3);
    // Each line is a complete JSON row.
    let row0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(row0["msg"], "first");
    let row2: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(row2["id"], 3);

    // Cursor advanced to the last row's `ts`.
    assert_eq!(cursor.current(), "T-300");
}

#[tokio::test]
async fn substitutes_cursor_in_url_and_query_on_subsequent_polls() {
    let logs = MockServer::start().await;
    let token = mock_token_server("bearer-B").await;

    // First call: ?since=X-INIT
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(query_param("since", "X-INIT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{"id": 1, "ts": "T-1"}],
        })))
        .up_to_n_times(1)
        .mount(&logs)
        .await;
    // Second call: ?since=T-1 (cursor advanced).
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(query_param("since", "T-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{"id": 2, "ts": "T-2"}],
        })))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(
        format!("{}/logs", logs.uri()),
        "$.events",
        Some("$.events[-1].ts"),
    );
    cfg.query.insert("since".into(), "{cursor}".into());
    cfg.auth = bearer_refresh_cfg(&token);

    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();

    for expected_count in [1, 1] {
        let mut buf = Vec::new();
        let n = poll_once(
            &cfg,
            &client(),
            &provider,
            &mut cursor,
            &rows_path,
            &reqwest::Method::GET,
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(n, expected_count);
    }
    assert_eq!(cursor.current(), "T-2");
}

#[tokio::test]
async fn handles_401_with_token_refresh_and_retry() {
    let logs = MockServer::start().await;
    let token_server = MockServer::start().await;

    // Token server: first call → token "stale", second call → "fresh".
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "stale",
            "expires_in": 3600,
        })))
        .up_to_n_times(1)
        .mount(&token_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh",
            "expires_in": 3600,
        })))
        .mount(&token_server)
        .await;

    // Log server: stale → 401; fresh → 200.
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(header("authorization", "Bearer stale"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&logs)
        .await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(header("authorization", "Bearer fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{"id": 99, "ts": "AFTER-RETRY"}],
        })))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(
        format!("{}/logs", logs.uri()),
        "$.events",
        Some("$.events[-1].ts"),
    );
    cfg.auth = bearer_refresh_cfg(&token_server);

    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let n = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await
    .expect("poll");
    assert_eq!(n, 1);
    assert_eq!(cursor.current(), "AFTER-RETRY");
}

#[tokio::test]
async fn returns_auth_error_when_refresh_doesnt_help() {
    let logs = MockServer::start().await;
    let token_server = mock_token_server("dud").await;

    // Always 401, even with a fresh token.
    Mock::given(method("GET"))
        .and(path("/logs"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(format!("{}/logs", logs.uri()), "$.events", None);
    cfg.auth = bearer_refresh_cfg(&token_server);

    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let result = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await;
    match result {
        Err(PollError::Auth) => {}
        other => panic!("expected PollError::Auth, got {:?}", other),
    }
}

#[tokio::test]
async fn handles_nested_supabase_analytics_shape() {
    // Real Supabase response is { result: { result: [ ... ], error: null } }.
    // The driver-side normalize unwraps `result.result`; this tests that
    // rows_json_path can target the inner array directly.
    let logs = MockServer::start().await;
    let token = mock_token_server("sb-token").await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/abc/analytics/endpoints/logs.all"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "result": {
                "result": [
                    {"id": "uuid-1", "event_message": "hello", "timestamp": 1000000},
                    {"id": "uuid-2", "event_message": "world", "timestamp": 2000000},
                ],
                "error": null,
            }
        })))
        .mount(&logs)
        .await;

    let cfg_endpoint = format!(
        "{}/v1/projects/abc/analytics/endpoints/logs.all",
        logs.uri()
    );
    let mut cfg = build_cfg(cfg_endpoint, "$.result.result", None);
    cfg.auth = bearer_refresh_cfg(&token);

    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let n = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await
    .unwrap();
    assert_eq!(n, 2);
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.trim_end().split('\n').collect();
    assert_eq!(lines.len(), 2);
    let row0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(row0["event_message"], "hello");
}

#[tokio::test]
async fn empty_rows_response_emits_nothing_and_keeps_cursor() {
    let logs = MockServer::start().await;
    let token = mock_token_server("idle").await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": []
        })))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(
        format!("{}/logs", logs.uri()),
        "$.events",
        Some("$.events[-1].ts"),
    );
    cfg.auth = bearer_refresh_cfg(&token);
    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let n = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await
    .unwrap();
    assert_eq!(n, 0);
    assert!(buf.is_empty());
    // Cursor stays put when nothing came back.
    assert_eq!(cursor.current(), "X-INIT");
}

#[tokio::test]
async fn non_2xx_non_401_surfaces_as_other_error_without_killing_loop() {
    let logs = MockServer::start().await;
    let token = mock_token_server("fine").await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(format!("{}/logs", logs.uri()), "$.events", None);
    cfg.auth = bearer_refresh_cfg(&token);
    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let result = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await;
    match result {
        Err(PollError::Other(_)) => {}
        other => panic!("expected PollError::Other, got {:?}", other),
    }
}

#[tokio::test]
async fn cursor_substitution_works_in_url_path_not_just_query() {
    let logs = MockServer::start().await;
    let token = mock_token_server("path-sub").await;
    Mock::given(method("GET"))
        .and(path("/v1/cursor-was-X-INIT/logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "events": [{"id": 1, "ts": "x"}],
        })))
        .mount(&logs)
        .await;

    let mut cfg = build_cfg(
        format!("{}/v1/cursor-was-{{cursor}}/logs", logs.uri()),
        "$.events",
        None,
    );
    // Disable wiremock's path matcher escape by ensuring the literal
    // {cursor} survives until cursor::substitute runs. (Format string
    // already escaped via {{ ... }}.)
    let _ = cfg.endpoint.contains("{cursor}");
    cfg.auth = bearer_refresh_cfg(&token);
    let provider: Arc<dyn TokenProvider> = auth::build(&cfg.auth).unwrap();
    let mut cursor = Cursor::new(&cfg.cursor).unwrap();
    let rows_path = JsonPath::parse(&cfg.rows.json_path).unwrap();
    let mut buf = Vec::new();
    let n = poll_once(
        &cfg,
        &client(),
        &provider,
        &mut cursor,
        &rows_path,
        &reqwest::Method::GET,
        &mut buf,
    )
    .await
    .unwrap();
    assert_eq!(n, 1);
}
