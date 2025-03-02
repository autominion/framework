use actix_web::{get, post, web, Error, HttpMessage, HttpRequest, HttpResponse, Responder};
use bytes::Bytes;
use futures::StreamExt;
use reqwest::Client;

use crate::errors::create_git_error_message;
use crate::parse_commands::{parse_update_requests, RefModification};
use crate::ForwardRepo;

/// GET /info/refs?service=<service>
///
/// This endpoint is used by Git clients to discover available refs. In protocol v2,
/// the handshake is initiated here. We forward both push (git-receive-pack)
/// and fetch (git-upload-pack) info requests.
#[get("/info/refs")]
// False positive: the RefCell `extensions` is not used accross the await point
#[allow(clippy::await_holding_refcell_ref)]
async fn info_refs_handler(req: HttpRequest) -> impl Responder {
    let query = req.query_string();
    if !query.contains("service=git-receive-pack") && !query.contains("service=git-upload-pack") {
        return HttpResponse::BadRequest().body("Unsupported or missing service");
    };

    let extensions = req.extensions();
    let forward = extensions.get::<ForwardRepo>().expect("ForwardRepo extension not found");

    let mut forward_url = forward.url.clone();
    forward_url.path_segments_mut().unwrap().push("info");
    forward_url.path_segments_mut().unwrap().push("refs");
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

/// POST /git-receive-pack
///
/// This endpoint is used by Git clients to push updates.
/// We first inspect the push commands to ensure that they only affect the allowed ref,
/// and if so we forward the entire request.
#[post("/git-receive-pack")]
// False positive: the RefCell `extensions` is not used accross the await point
#[allow(clippy::await_holding_refcell_ref)]
async fn git_receive_pack_handler(
    req: HttpRequest,
    mut payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    let body_bytes = body.freeze();

    let extensions = req.extensions();
    let forward = extensions.get::<ForwardRepo>().expect("ForwardRepo extension not found");

    match parse_update_requests(&body_bytes) {
        Ok(refs) => {
            for r in refs {
                if r.ref_name() != forward.allowed_ref {
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

    let mut forward_url = forward.url.clone();
    forward_url.path_segments_mut().unwrap().push("git-receive-pack");
    let basic_auth_user = forward.basic_auth_user.clone();
    let basic_auth_pass = forward.basic_auth_pass.clone();

    let client = Client::new();
    match client
        .post(forward_url)
        .basic_auth(basic_auth_user, Some(basic_auth_pass))
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
            let resp_body = resp.bytes().await.unwrap_or_else(|_| bytes::Bytes::new());
            Ok(HttpResponse::build(status)
                .insert_header(("Content-Type", content_type))
                .body(resp_body))
        }
        Err(err) => {
            log::error!("Error forwarding git-receive-pack: {:?}", err);
            let error_body = create_git_error_message("Error forwarding push");
            Ok(HttpResponse::Ok()
                .content_type("application/x-git-receive-pack-result")
                .body(error_body))
        }
    }
}

/// POST /git-upload-pack
///
/// This endpoint is used by Git clients to fetch objects (clone or fetch).
/// Unlike push, no ref restrictions are needed, so we simply forward the request.
#[post("/git-upload-pack")]
// False positive: the RefCell `extensions` is not used accross the await point
#[allow(clippy::await_holding_refcell_ref)]
async fn git_upload_pack_handler(
    req: HttpRequest,
    mut payload: web::Payload,
) -> Result<HttpResponse, Error> {
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    let body_bytes = body.freeze();

    let extensions = req.extensions();
    let forward = extensions.get::<ForwardRepo>().expect("ForwardRepo extension not found");
    let mut forward_url = forward.url.clone();
    forward_url.path_segments_mut().unwrap().push("git-upload-pack");
    let basic_auth_user = forward.basic_auth_user.clone();
    let basic_auth_pass = forward.basic_auth_pass.clone();

    let client = Client::new();
    match client
        .post(forward_url)
        .basic_auth(basic_auth_user, Some(basic_auth_pass))
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
            Ok(HttpResponse::build(status)
                .insert_header(("Content-Type", content_type))
                .body(resp_body))
        }
        Err(err) => {
            log::error!("Error forwarding git-upload-pack: {:?}", err);
            Ok(HttpResponse::InternalServerError().body("Error forwarding fetch"))
        }
    }
}
