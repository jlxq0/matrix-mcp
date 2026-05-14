//! MCP service implementation using the `rmcp` crate's Streamable HTTP
//! transport. Tools defined here are dispatched per JSON-RPC `tools/call`.
//!
//! Per-request authenticated identity is propagated by `auth::bearer_auth`,
//! which inserts an `AuthenticatedIdentity` into `request.extensions`. The
//! rmcp streamable-http tower layer then injects the original
//! `http::request::Parts` (with our extension on it) into the tool's
//! `RequestContext.extensions`. Tools read it via the `identity_from_ctx`
//! helper. A `task_local` won't work here because the rmcp session worker
//! runs in a separately-spawned task that doesn't inherit task-locals.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Serialize;

use crate::mas::AuthenticatedIdentity;

/// The MCP service. Empty state by design — per-request data comes from the
/// `RequestContext.extensions` (which rmcp populates with the original HTTP
/// `Parts`). Phase 2 adds a per-user Matrix-client cache here.
///
/// `tool_router` is consumed by the `#[tool_handler]` macro to dispatch tool
/// calls.
#[derive(Debug, Clone)]
pub struct MatrixMcpService {
    tool_router: ToolRouter<Self>,
}

impl MatrixMcpService {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for MatrixMcpService {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WhoamiResult {
    /// Matrix user id (e.g. `@alice:example.com`).
    pub mxid: String,
    /// Matrix device id the OAuth token is bound to, if any.
    pub device_id: Option<String>,
}

#[tool_router]
impl MatrixMcpService {
    /// Identity sanity-check. Returns the authenticated MXID and bound
    /// device id; useful for verifying the OAuth + introspection chain
    /// without involving any Matrix calls.
    #[tool(description = "Return the authenticated Matrix user id and device id.")]
    // rmcp tool dispatch always passes `&self` and `RequestContext` by value;
    // we can't take `ctx` by reference without breaking the tool ABI.
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    fn whoami(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let id = identity_from_ctx(&ctx).ok_or_else(|| {
            ErrorData::internal_error(
                "no authenticated identity in request context; router misconfiguration",
                None,
            )
        })?;
        let result = WhoamiResult {
            mxid: id.mxid,
            device_id: id.device_id,
        };
        Ok(rmcp::model::CallToolResult::structured(
            serde_json::to_value(&result).map_err(|e| {
                ErrorData::internal_error(format!("serialize whoami result: {e}"), None)
            })?,
        ))
    }
}

// `#[tool_handler]` auto-implements `call_tool`, `list_tools`, and `get_tool`
// by delegating to the `tool_router` field. Using `router = self.tool_router`
// reuses the cached router on the service rather than rebuilding it on every
// call. Our hand-written `get_info` is preserved (the macro only generates
// `get_info` when not already present).
#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatrixMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Matrix MCP server for example.com. Read and (in future phases) \
                 write Matrix rooms on behalf of the authenticated user.",
        )
    }
}

/// Read the authenticated identity from an rmcp `RequestContext`.
///
/// The auth middleware puts an `AuthenticatedIdentity` on the axum request
/// extensions; rmcp's streamable-http tower layer then wraps the request's
/// `Parts` into `ctx.extensions` for tool handlers. Returns `None` only if
/// the middleware wasn't applied — a router misconfiguration.
pub fn identity_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<AuthenticatedIdentity> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AuthenticatedIdentity>().cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn service_constructs_with_tool_router() {
        let svc = MatrixMcpService::new();
        // Smoke test: get_info doesn't panic and reports tools capability.
        let info = svc.get_info();
        assert!(info.capabilities.tools.is_some());
    }
}
