use actix_web::{Error, HttpRequest};
use url::Url;

use crate::requests::CompletionRequest;

#[allow(async_fn_in_trait)]
pub trait ProxyConfig: Send + Sync + 'static {
    /// The type of context extracted from the incoming request.
    type Context;

    /// Extract any necessary context from the incoming request.
    async fn extract_context(&self, req: &HttpRequest) -> Result<Self::Context, Error>;

    /// The API key that should be used when forwarding the request.
    async fn api_key(&self, ctx: &Self::Context, req: &CompletionRequest) -> Result<String, Error>;

    /// The URL to forward the request to.
    async fn forward_to_url(
        &self,
        ctx: &Self::Context,
        req: &CompletionRequest,
    ) -> Result<Url, Error>;

    /// Optionally handle the interaction after the reqest has been forwarded.
    /// In a streaming scenario, the response will be `None`.
    async fn inspect_interaction(
        &self,
        ctx: &Self::Context,
        req: &CompletionRequest,
        response: Option<serde_json::Value>,
    );
}
