use actix_web::{get, post, web, Error, HttpMessage, HttpRequest, HttpResponse, Responder};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use reqwest::Client;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::packet_line::advertisement::create_git_advertisement;
use crate::packet_line::errors::create_git_error_message;
use crate::packet_line::parse_commands::{parse_update_requests, RefModification};
use crate::{Forward, ForwardToLocal, ForwardToRemote, ProxyBehaivor};

/// GET /info/refs?service=<service>
///
/// This endpoint is used by Git clients to discover available refs. In protocol v2,
/// the handshake is initiated here. We forward both push (git-receive-pack)
/// and fetch (git-upload-pack) info requests.
#[get("/info/refs")]
async fn info_refs_handler(req: HttpRequest) -> impl Responder {
    let query = req.query_string();
    if !query.contains("service=git-receive-pack") && !query.contains("service=git-upload-pack") {
        return HttpResponse::BadRequest().body("Unsupported or missing service");
    }

    let behaivor = proxy_behaivor(&req);
    match behaivor.forward {
        Forward::ForwardToRemote(ref forward) => remote_info_refs(forward, query).await,
        Forward::ForwardToLocal(ref local) => local_info_refs(local, query).await,
    }
}

async fn remote_info_refs(forward: &ForwardToRemote, query: &str) -> HttpResponse {
    let mut forward_url = forward.url.clone();
    {
        let mut segments = forward_url.path_segments_mut().expect("Cannot modify URL segments");
        segments.push("info");
        segments.push("refs");
    }
    forward_url.set_query(Some(query));

    let client = Client::new();
    match client
        .get(forward_url)
        .basic_auth(forward.basic_auth_user.clone(), Some(forward.basic_auth_pass.clone()))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let body = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
            HttpResponse::build(status).insert_header(("Content-Type", content_type)).body(body)
        }
        Err(err) => {
            log::error!("Error forwarding info/refs: {:?}", err);
            HttpResponse::InternalServerError().body("Error forwarding request")
        }
    }
}

async fn local_info_refs(forward: &ForwardToLocal, query: &str) -> HttpResponse {
    let (service, content_type) = if query.contains("service=git-receive-pack") {
        ("git-receive-pack", "application/x-git-receive-pack-advertisement")
    } else if query.contains("service=git-upload-pack") {
        ("git-upload-pack", "application/x-git-upload-pack-advertisement")
    } else {
        return HttpResponse::BadRequest().body("Unsupported or missing service");
    };

    let output =
        match Command::new(service).arg("--advertise-refs").arg(&forward.path).output().await {
            Ok(o) => o,
            Err(err) => {
                log::error!("Error spawning {}: {:?}", service, err);
                return HttpResponse::InternalServerError()
                    .body(format!("Error spawning {}", service));
            }
        };

    if !output.status.success() {
        log::error!("Command {} exited with non-zero status", service);
        return HttpResponse::InternalServerError().body("Error processing info/refs");
    }

    // Prepend the Git advertisement header.
    let advertisement = create_git_advertisement(service, &output.stdout);

    HttpResponse::Ok().content_type(content_type).body(advertisement)
}

/// POST /git-receive-pack
///
/// This endpoint is used by Git clients to push updates.
/// We first inspect the push commands to ensure that they only affect the allowed ref,
/// and if so we forward the entire request.
#[post("/git-receive-pack")]
async fn git_receive_pack_handler(
    req: HttpRequest,
    mut payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    let body_bytes = body.freeze();

    let behaivor = proxy_behaivor(&req);

    match parse_update_requests(&body_bytes) {
        Ok(refs) => {
            for r in refs {
                if r.ref_name() != behaivor.allowed_ref {
                    log::warn!("Push attempted to disallowed ref: {}", r.ref_name());
                    let error_body =
                        create_git_error_message("Push not allowed to modify this ref");
                    return Ok(HttpResponse::Ok()
                        .content_type("application/x-git-receive-pack-result")
                        .body(error_body));
                }
                match r {
                    RefModification::Create { .. } => {
                        log::warn!("Push attempted to create ref: {}", r.ref_name());
                        let error_body =
                            create_git_error_message("Push not allowed to create this ref");
                        return Ok(HttpResponse::Ok()
                            .content_type("application/x-git-receive-pack-result")
                            .body(error_body));
                    }
                    RefModification::Delete { .. } => {
                        log::warn!("Push attempted to delete ref: {}", r.ref_name());
                        let error_body =
                            create_git_error_message("Push not allowed to delete this ref");
                        return Ok(HttpResponse::Ok()
                            .content_type("application/x-git-receive-pack-result")
                            .body(error_body));
                    }
                    RefModification::Update { .. } => {}
                }
            }
        }
        Err(e) => {
            log::error!("Error parsing push commands: {:?}", e);
            let error_body = create_git_error_message("Invalid push data");
            return Ok(HttpResponse::Ok()
                .content_type("application/x-git-receive-pack-result")
                .body(error_body));
        }
    }

    let response = match behaivor.forward {
        Forward::ForwardToRemote(ref forward) => remote_git_receive_pack(forward, body_bytes).await,
        Forward::ForwardToLocal(ref local) => local_git_receive_pack(local, body_bytes).await,
    };

    Ok(response)
}

async fn remote_git_receive_pack(forward: &ForwardToRemote, body_bytes: Bytes) -> HttpResponse {
    let mut forward_url = forward.url.clone();
    {
        let mut segments = forward_url.path_segments_mut().expect("Cannot modify URL segments");
        segments.push("git-receive-pack");
    }
    let client = Client::new();
    match client
        .post(forward_url)
        .basic_auth(forward.basic_auth_user.clone(), Some(forward.basic_auth_pass.clone()))
        .header("Content-Type", "application/x-git-receive-pack-request")
        .body(body_bytes.clone())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let resp_body = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
            HttpResponse::build(status)
                .insert_header(("Content-Type", content_type))
                .body(resp_body)
        }
        Err(err) => {
            log::error!("Error forwarding git-receive-pack: {:?}", err);
            let error_body = create_git_error_message("Error forwarding push");
            HttpResponse::Ok()
                .content_type("application/x-git-receive-pack-result")
                .body(error_body)
        }
    }
}

async fn local_git_receive_pack(forward: &ForwardToLocal, body_bytes: Bytes) -> HttpResponse {
    let mut child = match Command::new("git-receive-pack")
        .arg("--stateless-rpc")
        .arg(&forward.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            log::error!("Error spawning git-receive-pack: {:?}", err);
            let error_body = create_git_error_message("Error spawning git-receive-pack");
            return HttpResponse::Ok()
                .content_type("application/x-git-receive-pack-result")
                .body(error_body);
        }
    };

    // Write the request body to the child’s stdin.
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(&body_bytes).await {
            log::error!("Error writing to git-receive-pack stdin: {:?}", err);
        }
    }

    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(err) => {
            log::error!("Error waiting for git-receive-pack: {:?}", err);
            let error_body = create_git_error_message("Error processing push");
            return HttpResponse::Ok()
                .content_type("application/x-git-receive-pack-result")
                .body(error_body);
        }
    };

    if !output.status.success() {
        log::error!("git-receive-pack exited with non-zero status");
        let error_body = create_git_error_message("git-receive-pack failed");
        return HttpResponse::Ok()
            .content_type("application/x-git-receive-pack-result")
            .body(error_body);
    }

    HttpResponse::Ok().content_type("application/x-git-receive-pack-result").body(output.stdout)
}

/// POST /git-upload-pack
///
/// This endpoint is used by Git clients to fetch objects (clone or fetch).
/// Unlike push, no ref restrictions are needed, so we simply forward the request.
#[post("/git-upload-pack")]
async fn git_upload_pack_handler(
    req: HttpRequest,
    mut payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    let body_bytes = body.freeze();

    let behaivor = proxy_behaivor(&req);
    let response = match behaivor.forward {
        Forward::ForwardToRemote(ref forward) => remote_git_upload_pack(forward, body_bytes).await,
        Forward::ForwardToLocal(ref local) => local_git_upload_pack(local, body_bytes).await,
    };

    Ok(response)
}

async fn remote_git_upload_pack(forward: &ForwardToRemote, body_bytes: Bytes) -> HttpResponse {
    let mut forward_url = forward.url.clone();
    {
        let mut segments = forward_url.path_segments_mut().expect("Cannot modify URL segments");
        segments.push("git-upload-pack");
    }
    let client = Client::new();
    match client
        .post(forward_url)
        .basic_auth(forward.basic_auth_user.clone(), Some(forward.basic_auth_pass.clone()))
        .header("Content-Type", "application/x-git-upload-pack-request")
        .body(body_bytes.clone())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let content_type = resp
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let resp_body = resp.bytes().await.unwrap_or_else(|_| Bytes::new());
            HttpResponse::build(status)
                .insert_header(("Content-Type", content_type))
                .body(resp_body)
        }
        Err(err) => {
            log::error!("Error forwarding git-upload-pack: {:?}", err);
            HttpResponse::InternalServerError().body("Error forwarding fetch")
        }
    }
}

async fn local_git_upload_pack(forward: &ForwardToLocal, body_bytes: Bytes) -> HttpResponse {
    let mut child = match Command::new("git-upload-pack")
        .arg("--stateless-rpc")
        .arg(&forward.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            log::error!("Error spawning git-upload-pack: {:?}", err);
            return HttpResponse::InternalServerError().body("Error spawning git-upload-pack");
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(&body_bytes).await {
            log::error!("Error writing to git-upload-pack stdin: {:?}", err);
        }
    }

    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(err) => {
            log::error!("Error waiting for git-upload-pack: {:?}", err);
            return HttpResponse::InternalServerError().body("Error processing fetch");
        }
    };

    if !output.status.success() {
        log::error!("git-upload-pack exited with non-zero status");
        return HttpResponse::InternalServerError().body("git-upload-pack failed");
    }

    HttpResponse::Ok().content_type("application/x-git-upload-pack-result").body(output.stdout)
}

/// Extract the `ProxyBehaivor` from the request extensions.
fn proxy_behaivor(request: &HttpRequest) -> ProxyBehaivor {
    let extensions = request.extensions();
    extensions.get::<ProxyBehaivor>().expect("ProxyBehaivor extension not found").clone()
}
