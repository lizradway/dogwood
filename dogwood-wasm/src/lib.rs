//! TypeScript / WebAssembly bindings for the Dogwood policy frontend.
//!
//! This crate is a thin `wasm-bindgen` shell over the same curated public
//! surface of `dogwood-language` that the `dogwood` CLI drives. The operations
//! ([`ops`]) are `&str` in, owned-serializable-report out; here we expose them
//! to JavaScript, converting each report to a real JS object (via
//! `serde-wasm-bindgen`, with TS `interface`s emitted by `tsify`) and each
//! fatal error to a thrown `Error` carrying the structured diagnostic.
//!
//! ## Surface
//!
//! | JS function            | Dogwood op            | Needs action schema? |
//! |------------------------|-----------------------|----------------------|
//! | `checkParse`           | parse + macro expand  | no                   |
//! | `validate`             | lower + type-check    | yes                  |
//! | `lower`                | lower to Cedar        | yes                  |
//! | `replay`               | lower + replay trace  | yes                  |
//! | `checkActionSchema`    | Cedar schema check    | (is the schema)      |
//! | `checkEventSchema`     | event-schema check    | no                   |
//! | `checkProviders`       | providers.json check  | no                   |
//! | `mcpToCedarSchema`     | MCP manifest -> Cedar | no                   |

mod error;
pub mod live;
mod ops;
pub(crate) mod providers;

use wasm_bindgen::prelude::*;

use error::OpError;
use ops::SchemaInputs;

// The live, stateful authorizer (lower once, feed events as they happen), the
// counterpart to the one-shot `replay` above.
pub use live::{AuthorizerDecision, DogwoodAuthorizer, EntityInput, EntityRef, EventInput};

// Re-export the report types so their `Tsify`-generated TS interfaces are in
// scope for the exported function signatures below.
pub use error::{Diagnostic, Label, Severity};
pub use ops::{
    CheckParseReport, LowerArtifacts, PolicySummary, ReplayReport, SchemaCheckReport,
    TimepointVerdict, ValidateReport, Verdict,
};

// ─── error shape (documented for the thrown Error's `.diagnostic`) ─────
//
// Fatal errors are thrown as JS `Error`s. The human message is `error.message`;
// the structured diagnostic (the same JSON the CLI's `--format json` emits) is
// attached as `error.diagnostic`, typed here so consumers get completion on it.
#[wasm_bindgen(typescript_custom_section)]
const TS_ERROR: &'static str = r#"
/** The structured payload attached to a thrown Dogwood error as `.diagnostic`. */
export interface DogwoodDiagnostic {
  severity: Severity;
  code?: string;
  message: string;
  labels?: Label[];
  help?: string;
  spanned: boolean;
  /** Follow-on findings (e.g. the 2nd..Nth of a batch of parse errors). */
  related?: Diagnostic[];
}
export interface DogwoodError extends Error {
  diagnostic: DogwoodDiagnostic;
}
"#;

/// Install a panic hook so a Rust panic surfaces as a readable `console.error`
/// (a panic in wasm otherwise aborts with an opaque `unreachable`). Idempotent;
/// call once at startup. Automatically invoked on module load via `start`.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ─── error conversion ──────────────────────────────────────────────────

/// Turn a fatal [`OpError`] into a thrown JS `Error`: `.message` is the human
/// text, `.diagnostic` is the structured JSON contract (via `JSON.parse` of the
/// serde output, so the exact shape is preserved regardless of `#[serde]`
/// attributes like `flatten`).
pub(crate) fn throw(e: OpError) -> JsValue {
    let err = js_sys::Error::new(&e.to_string());
    err.set_name("DogwoodError");
    if let Ok(json) = serde_json::to_string(&e) {
        if let Ok(parsed) = js_sys::JSON::parse(&json) {
            let _ = js_sys::Reflect::set(&err, &JsValue::from_str("diagnostic"), &parsed);
        }
    }
    err.into()
}

/// Build the optional service-schema overrides from three optional strings.
///
/// Fallible only because of the `scriptFile` guard (see [`providers`]): supplied
/// provider text is parsed here purely to reject a declaration that cannot work
/// in wasm, and then parsed again by [`ops::SchemaInputs`], which is verbatim
/// from `dogwood-cli` and so cannot carry the check itself. Two parses of a small
/// JSON document, only when providers are supplied at all, is the right price for
/// keeping `ops` a byte-for-byte copy.
fn inputs<'a>(
    event_schema: Option<&'a str>,
    providers: Option<&'a str>,
    macros: Option<&'a str>,
) -> Result<SchemaInputs<'a>, OpError> {
    if let Some(json) = providers {
        crate::providers::parse_declarations(json)?;
    }
    Ok(SchemaInputs {
        event_schema,
        providers,
        macros,
    })
}

// ─── exported operations ────────────────────────────────────────────────

/// Parse and macro-expand a `.dw` policy set, reporting syntax/macro errors and
/// per-policy structural summaries. Needs no action schema.
#[wasm_bindgen(js_name = checkParse)]
pub fn check_parse(
    source: &str,
    event_schema: Option<String>,
    providers: Option<String>,
    macros: Option<String>,
) -> Result<CheckParseReport, JsValue> {
    let schema =
        inputs(event_schema.as_deref(), providers.as_deref(), macros.as_deref()).map_err(throw)?;
    ops::check_parse(source, &schema).map_err(throw)
}

/// Lower against the Cedar action schema and type-check. Fatal parse/lower
/// errors throw; a successful lower with type findings returns the report.
#[wasm_bindgen]
pub fn validate(
    source: &str,
    action_schema: &str,
    event_schema: Option<String>,
    providers: Option<String>,
    macros: Option<String>,
) -> Result<ValidateReport, JsValue> {
    let schema =
        inputs(event_schema.as_deref(), providers.as_deref(), macros.as_deref()).map_err(throw)?;
    ops::validate_policies(source, &schema, action_schema).map_err(throw)
}

/// Lower a `.dw` policy set to Cedar and return the emitted artifacts (policies
/// and augmented schema, in text and Cedar-JSON forms).
#[wasm_bindgen]
pub fn lower(
    source: &str,
    action_schema: &str,
    event_schema: Option<String>,
    providers: Option<String>,
    macros: Option<String>,
) -> Result<LowerArtifacts, JsValue> {
    let schema =
        inputs(event_schema.as_deref(), providers.as_deref(), macros.as_deref()).map_err(throw)?;
    ops::lower_to_cedar(source, &schema, action_schema).map_err(throw)
}

/// Lower, then drive a `.log` event trace through a stateful authorizer,
/// returning the per-decision verdict stream.
#[wasm_bindgen]
pub fn replay(
    source: &str,
    action_schema: &str,
    log: &str,
    event_schema: Option<String>,
    providers: Option<String>,
    macros: Option<String>,
) -> Result<ReplayReport, JsValue> {
    let schema =
        inputs(event_schema.as_deref(), providers.as_deref(), macros.as_deref()).map_err(throw)?;
    ops::replay_trace(source, &schema, action_schema, log).map_err(throw)
}

/// Check a Cedar action schema (`.cedarschema`) in isolation.
#[wasm_bindgen(js_name = checkActionSchema)]
pub fn check_action_schema(source: &str) -> Result<SchemaCheckReport, JsValue> {
    ops::check_action_schema(source).map_err(throw)
}

/// Check an event-schema DSL (`.dwschema`) in isolation.
#[wasm_bindgen(js_name = checkEventSchema)]
pub fn check_event_schema(source: &str) -> Result<SchemaCheckReport, JsValue> {
    ops::check_event_schema(source).map_err(throw)
}

/// Check an information-provider declarations file (`providers.json`) in
/// isolation.
#[wasm_bindgen(js_name = checkProviders)]
pub fn check_providers(json: &str) -> Result<SchemaCheckReport, JsValue> {
    // The `scriptFile` guard runs first, so a declaration that is well-formed but
    // unusable here throws rather than reporting `ok: true` — see `providers`.
    providers::parse_declarations(json).map_err(throw)?;
    ops::check_providers(json).map_err(throw)
}

/// Generate a Cedar action schema (`.cedarschema` text) from an MCP
/// `tools/list` manifest, layered on the embedded Drupe template.
#[wasm_bindgen(js_name = mcpToCedarSchema)]
pub fn mcp_to_cedar_schema(manifest_json: &str) -> Result<String, JsValue> {
    ops::generate_mcp_schema(manifest_json).map_err(throw)
}
