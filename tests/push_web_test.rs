//! Integration tests for push_web. Uses wiremock as fake VAPID endpoint.

use vpn_api::push_web::{send_one, Subscription};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

// Real generated test VAPID keypair (generated for this test, NOT used in prod).
// Generate fresh ones with: npx web-push generate-vapid-keys --json
const TEST_PRIVATE_B64URL: &str = "cexcysWTDB-4WLdkFWOkrBJsjWxI5cs4eOyzhZXm-II";
const TEST_P256DH_B64URL: &str =
    "BA0q7G-rNH_sa_3571ziYIt7iTCCjt5cy_834no-W7lc9pDMIvUaxJt8Yh_Pasz0cuYyALgNP6COXgGXamYKWgs";
const TEST_AUTH_B64URL: &str = "2CD9zrah058Sa1UMzbW-Sg";

#[tokio::test]
async fn send_one_hits_endpoint_with_201() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mock)
        .await;

    let sub = Subscription {
        endpoint: format!("{}/wp/abc", mock.uri()),
        p256dh: TEST_P256DH_B64URL.to_string(),
        auth: TEST_AUTH_B64URL.to_string(),
    };
    let payload = serde_json::json!({"title": "test", "body": "hi"});

    let res = send_one(&sub, TEST_PRIVATE_B64URL, "mailto:t@t", &payload).await;
    assert!(res.is_ok(), "expected Ok, got {:?}", res);
}

#[tokio::test]
async fn send_one_returns_404_when_endpoint_not_found() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let sub = Subscription {
        endpoint: format!("{}/wp/dead", mock.uri()),
        p256dh: TEST_P256DH_B64URL.to_string(),
        auth: TEST_AUTH_B64URL.to_string(),
    };
    let payload = serde_json::json!({});

    let res = send_one(&sub, TEST_PRIVATE_B64URL, "mailto:t@t", &payload).await;
    assert_eq!(res, Err(404));
}

#[tokio::test]
async fn send_one_returns_410_when_endpoint_gone() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(410))
        .mount(&mock)
        .await;

    let sub = Subscription {
        endpoint: format!("{}/wp/gone", mock.uri()),
        p256dh: TEST_P256DH_B64URL.to_string(),
        auth: TEST_AUTH_B64URL.to_string(),
    };
    let payload = serde_json::json!({});

    let res = send_one(&sub, TEST_PRIVATE_B64URL, "mailto:t@t", &payload).await;
    assert_eq!(res, Err(410));
}
