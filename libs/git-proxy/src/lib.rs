//! A simple Git proxy integration for Actix Web that forwards Git requests to a Git server.
//! It supports the Git v2 wire protocol via the smart HTTP transfer protocol.
//! In other words, most modern Git clients should work with this proxy over HTTP.
//! For authentication, currently only HTTP Basic Authentication is supported, both for the proxy itself and for the upstream Git server.
//!
//! # Usage Example
//!
//! For a basic usage example, see the `basic` example in the `examples` directory.
//!
//! # How it Works
//!
//! 1. Client requests (e.g. `git clone`, `git push`, `git fetch`) are sent to
//!    your Actix Web server at the path defined in [`scope`].
//! 2. An optional Basic Authentication check (the validator you provide) runs,
//!    ensuring the request is authorized to access the proxy.
//!    This check needs to supply a [`ProxyBehaivor`] instance to the request extensions
//!    which will tell the proxy how to forward the Git requests.
//! 3. The proxy inspects the request body of push requests to apply any configured restrictions.
//!    Currently, push requests are restricted to a single specific ref (e.g. branch) configured by `allowed_ref`.
//!    deletion and creation of refs is forbidden.
//! 4. The proxy routes the request to the corresponding Git endpoints (`info/refs`,
//!    `git-receive-pack`, `git-upload-pack`) and relays the response from the upstream server back to the client.
//!
//! # References
//!
//! For more details on the Git HTTP protocol and the wire protocol v2, see:
//!
//! - [Git HTTP protocol documentation](https://git-scm.com/docs/http-protocol)
//! - [Git wire protocol v2 documentation](https://git-scm.com/docs/protocol-v2)

use std::future::Future;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{web, Error};
use actix_web_httpauth::extractors::basic::BasicAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use url::Url;

mod errors;
mod parse_commands;
mod parse_tests;
mod routes;

use routes::{git_receive_pack_handler, git_upload_pack_handler, info_refs_handler};

/// What the proxy should do with the request.
#[derive(Clone)]
pub enum ProxyBehaivor {
    /// Forward the request to another Git server.
    ForwardToRemote(ForwardToRemote),
}

/// Configuration details for forwarding Git requests to another server.
///
/// # Usage
///
/// In your authentication validator function, supply an instance of this struct to the Actix Web request extensions.
/// For a basic usage example, see the `basic` example in the `examples` directory.
///
/// # Fields
///
/// * `url` - The upstream Git server's URL to which Git commands are forwarded.
/// * `basic_auth_user` - The username used for Basic Authentication when
///                       communicating with the upstream server.
/// * `basic_auth_pass` - The password used for Basic Authentication when
///                       communicating with the upstream server.
/// * `allowed_ref`     - A reference (e.g., "refsrefs/heads/main") indicating which
///                       ref/branch is allowed to be updated during a push operation.
///                       Pushes to other will be denied.
#[derive(Clone)]
pub struct ForwardToRemote {
    pub url: Url,
    pub basic_auth_user: String,
    pub basic_auth_pass: String,
    pub allowed_ref: String,
}

/// Create an `actix_web::Scope` configured to handle the v2 wire protocol over the Git smart HTTP transfer protocol.
///
/// This function sets up the necessary routes (`info/refs`, `git-receive-pack`,
/// and `git-upload-pack`) under the given `path`, and applies a Basic
/// Authentication middleware using the provided validator function.
///
/// # Invariant
///
/// The `basic_auth_validator` function **MUST** insert a `ForwardRepo` instance into the request extensions.
/// **Otherwise the proxy will panic!**
///
/// # Arguments
///
/// * `path`                 - The base path under which the Git routes will be mounted (e.g., "/git").
/// * `basic_auth_validator` - A function that validates Basic Authentication credentials for each request.
/// # Returns
///
/// An `actix_web::Scope` containing the configured Git routes and middleware,
/// ready to be registered within an Actix `App`.
pub fn scope<O, F>(
    path: &str,
    basic_auth_validator: F,
) -> actix_web::Scope<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<EitherBody<BoxBody>>,
        Error = actix_web::Error,
        InitError = (),
    >,
>
where
    F: Fn(ServiceRequest, BasicAuth) -> O + 'static,
    O: Future<Output = Result<ServiceRequest, (Error, ServiceRequest)>> + 'static,
{
    let auth_middleware = HttpAuthentication::basic(basic_auth_validator);

    web::scope(path)
        .service(info_refs_handler)
        .service(git_receive_pack_handler)
        .service(git_upload_pack_handler)
        .wrap(auth_middleware)
}
