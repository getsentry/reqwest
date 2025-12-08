#![cfg(not(target_arch = "wasm32"))]
mod support;
use support::server;

use std::time::Duration;

#[tokio::test]
async fn stats_request_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // delay returning the response
            tokio::time::sleep(Duration::from_secs(2)).await;
            http::Response::default()
        }
    });

    let client = reqwest::Client::builder().build().unwrap();

    let url = format!("http://{}/slow", server.addr());

    let req = client
        .get(&url)
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let req_id = req.req_id().clone();

    let res = client.execute(req).await;

    let err = res.unwrap_err();

    if cfg!(not(target_arch = "wasm32")) {
        assert!(err.is_timeout() && !err.is_connect());
    } else {
        assert!(err.is_timeout());
    }

    let stats = hyper::stats::consume_request_stats(req_id);
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .is_some());
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .unwrap()
        .get_connect()
        .is_some());
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .unwrap()
        .get_dns_resolve()
        .is_some());
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .unwrap()
        .get_tls_connect()
        .is_none());
    assert!(stats.redirects()[0].get_request_sent().is_some());
    assert!(stats.redirects()[0].get_response_start().is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn stats_connect_timeout() {
    let _ = env_logger::try_init();

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(100))
        .build()
        .unwrap();

    let url = "http://10.255.255.1:81/slow";

    let req = client
        .get(url)
        .timeout(Duration::from_millis(1000))
        .build()
        .unwrap();
    let req_id = req.req_id().clone();
    let res = client.execute(req).await;

    let err = res.unwrap_err();

    assert!(err.is_connect() && err.is_timeout());

    let stats = hyper::stats::consume_request_stats(req_id);
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .is_some());
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .unwrap()
        .get_dns_resolve()
        .is_some());
    assert!(stats.redirects()[0]
        .get_http_stats()
        .get_connection_stats()
        .unwrap()
        .get_tls_connect()
        .is_none());
    assert!(stats.redirects()[0].get_request_sent().is_none());
    assert!(stats.redirects()[0].get_response_start().is_none());
}
