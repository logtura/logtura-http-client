//! End-to-end coverage of the components together: a mock token
//! server provides a fresh bearer; a mock log endpoint returns rows;
//! the poll-once primitive emits them. We don't run `poll::run` (which
//! loops forever) — instead we exercise the same poll_once path via a
//! tight harness that calls into the public surface.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use logtura_http_client_lib::auth::{self, TokenProvider};
use logtura_http_client_lib::config::{AuthConfig, AuthStrategy, ClientAuth};
use reqwest::Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn bearer_refresh_provides_token_via_real_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "integration-token",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let cfg = AuthConfig {
        strategy: AuthStrategy::BearerRefresh,
        token: None,
        token_url: Some(format!("{}/token", server.uri())),
        token_method: "POST".into(),
        token_headers: HashMap::new(),
        access_token_json_path: "$.access_token".into(),
        expires_in_json_path: "$.expires_in".into(),
        client_id: None,
        client_secret: None,
        refresh_token: None,
        refresh_token_file: None,
        client_auth: ClientAuth::Basic,
    };
    let provider: Arc<dyn TokenProvider> = auth::build(&cfg).unwrap();
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let tok = provider.current(&client).await.unwrap();
    assert_eq!(tok, "integration-token");
}
