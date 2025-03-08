use std::time::Duration;

use actix_web::{
    web::{self, Json},
    HttpRequest, HttpResponse, Scope,
};
use futures_util::StreamExt;
use reqwest::Client;
use url::Url;

use crate::config::ProxyConfig;
use crate::requests::CompletionRequest;

const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Create a `reqwest` client with lenient timeouts.
fn create_reqwest_client() -> Client {
    reqwest::Client::builder()
        .timeout(ROUNDTRIP_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .expect("Failed to build streaming HTTP client")
}

pub fn scope<C>(config: C) -> Scope
where
    C: ProxyConfig + Clone + 'static,
{
    web::scope("/chat").service(web::resource("/completions").route(web::post().to({
        let config = config.clone();
        move |req: HttpRequest, body: Json<CompletionRequest>| {
            let config = config.clone();
            completions(req, body, config)
        }
    })))
}

async fn completions<C: ProxyConfig>(
    req: HttpRequest,
    body: Json<CompletionRequest>,
    config: C,
) -> actix_web::Result<HttpResponse> {
    let ctx = config.extract_context(&req).await?;
    let request_payload = body.into_inner();

    let api_key = config.api_key(&ctx, &request_payload).await?;
    let target_url = config.forward_to_url(&ctx, &request_payload).await?;

    if request_payload.stream.unwrap_or(false) {
        config.inspect_interaction(&ctx, &request_payload, None).await;
        Ok(forward_stream_request(&api_key, target_url, &request_payload).await)
    } else {
        let (resp, response_json) =
            forward_non_stream_request(&api_key, target_url, &request_payload).await?;
        config.inspect_interaction(&ctx, &request_payload, response_json).await;
        Ok(resp)
    }
}

/// Forward a non-streaming request.
async fn forward_non_stream_request(
    api_key: &str,
    target_url: Url,
    request_payload: &CompletionRequest,
) -> actix_web::Result<(HttpResponse, Option<serde_json::Value>)> {
    let client = create_reqwest_client();
    let req_builder = client
        .post(target_url)
        .bearer_auth(api_key)
        .header("Content-Type", "application/json")
        .json(&request_payload);

    let resp = req_builder.send().await.map_err(|err| {
        log::error!("Failed to send request: {:?}", err);
        actix_web::error::ErrorInternalServerError(err)
    })?;

    let status = resp.status();
    let text_body = resp.text().await.map_err(|err| {
        log::error!("Failed to read response body: {:?}", err);
        actix_web::error::ErrorInternalServerError(err)
    })?;

    if status.is_success() {
        let response_json = serde_json::from_str(&text_body).ok();
        Ok((HttpResponse::Ok().body(text_body), response_json))
    } else if status.is_client_error() {
        Err(actix_web::error::ErrorBadRequest(text_body))
    } else {
        log::error!("Upstream error: status={} body={}", status, text_body);
        Err(actix_web::error::ErrorInternalServerError(text_body))
    }
}

/// Forward a streaming (SSE) request.
async fn forward_stream_request(
    api_key: &str,
    target_url: Url,
    request_payload: &CompletionRequest,
) -> HttpResponse {
    let client = create_reqwest_client();
    let req_builder = client
        .post(target_url)
        .bearer_auth(api_key)
        .header("Content-Type", "application/json")
        .json(&request_payload);

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(err) => {
            log::error!("Failed to send SSE request: {:?}", err);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let text_body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                log::error!("Failed to read SSE error body: {:?}", e);
                return HttpResponse::InternalServerError().finish();
            }
        };
        return if status.is_client_error() {
            HttpResponse::BadRequest().body(text_body)
        } else {
            log::error!("Upstream SSE error: status={} body={}", status, text_body);
            HttpResponse::InternalServerError().finish()
        };
    }

    let byte_stream = resp.bytes_stream().map(|chunk| match chunk {
        Ok(c) => Ok(c),
        Err(err) => {
            log::error!("Error reading SSE chunk: {:?}", err);
            Err(actix_web::error::ErrorInternalServerError(err))
        }
    });

    HttpResponse::Ok()
        .append_header(("Content-Type", "text/event-stream"))
        .append_header(("Cache-Control", "no-cache"))
        .streaming(byte_stream)
}
