//! The **live** (incremental) authorizer: Dogwood's stateful `Authorizer`
//! exposed to JavaScript as a class.
//!
//! [`ops::replay_trace`](crate::ops::replay_trace) answers "what would this
//! policy have decided over this recorded `.log` trace?" — it lowers, drives a
//! fresh authorizer over every event, and returns the whole verdict stream. A
//! host that is *making* decisions (an agent gateway, an MCP proxy) needs the
//! other shape: lower once, then feed events **one at a time** as they happen
//! and get a decision back per event, with the temporal history accumulating
//! across calls. That is what [`DogwoodAuthorizer`] is.
//!
//! ```js
//! const auth = new DogwoodAuthorizer(policySrc, actionSchemaSrc);
//! const d = auth.isAuthorized({
//!   action: 'Drupe::Action::Read',
//!   principal: { type: 'Drupe::User', id: 'alice' },
//!   resource:  { type: 'Drupe::Gateway', id: 'gw1' },
//!   context:   { input: { document: 'quarterly report', user: 'alice' } },
//! });
//! if (!d.allowed) throw new Error('denied');
//! ```
//!
//! ## Event shape
//!
//! [`EventInput`] mirrors the `.log` wire format's four components — the
//! `scope(...)` (principal/resource), the `entities(...)` store, the
//! `request_context(...)` bag, and the trailing **logged** record — because
//! those are exactly the parts the frontend's `EventBuilder` accepts. Entity
//! references are given **structured** (`{ type, id }`) rather than as
//! `Ns::Type::"id"` literals: the builder's `*_for` methods escape the id
//! canonically exactly once, so a JS host never has to (and cannot
//! double-)escape an id containing `"` or `\`.
//!
//! `logged` vs `context` is a real distinction, not a convenience split:
//! `logged` is the durable temporal record that future events correlate
//! against, `context` is the ephemeral per-decision Cedar request context. A
//! field both halves need (typically `input`) must be supplied in **both** —
//! the frontend is deliberately explicit about this, and so are these bindings.
//!
//! ## Known gap
//!
//! The event schema declares two top-level *scalar* logged fields
//! (`requestId`, `sessionId`). The frontend's public `EventBuilder` can only
//! set logged fields nested under a group (`field(group, name, value)`), so
//! those two are not reachable through any out-of-crate caller — the `.log`
//! parser builds `EventData` directly, which is crate-internal. Policies that
//! pin on `requestId`/`sessionId` therefore need the whole-trace
//! [`replay`](crate::replay) path rather than this one.

use std::collections::BTreeMap;

use dogwood_language::{Authorizer, Decision, Event, EventBuilder, Value};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::error::OpError;
use crate::ops::{SchemaInputs, Verdict, lower_for_authorizer};

// ─── the JS value type ───────────────────────────────────────────────

/// The TS type for a Dogwood field value. Declared as a custom section rather
/// than derived, because it is recursive and carries the two tagged escapes
/// (`__entity` / `__decimal`) that JSON alone cannot express.
#[wasm_bindgen(typescript_custom_section)]
const TS_VALUE: &'static str = r#"
/**
 * A Dogwood field value. JSON values map to their Dogwood counterparts;
 * non-integer numbers become decimals. Two tagged forms cover what JSON
 * cannot express:
 *
 *  - `{ __entity: { type, id } }` — an entity reference
 *  - `{ __decimal: "1.50" }` — a decimal with exact text preserved (a JS
 *    number would round-trip `1.50` as `1.5`)
 */
export type DogwoodValue =
  | null
  | boolean
  | number
  | string
  | DogwoodValue[]
  | { __entity: EntityRef }
  | { __decimal: string }
  | { [key: string]: DogwoodValue };
"#;

// ─── event input ─────────────────────────────────────────────────────

/// A structured entity reference, deserialized from `{ type, id }`.
#[derive(Debug, Clone, Deserialize, tsify_next::Tsify)]
pub struct EntityRef {
    /// Entity type, namespace included (`"Drupe::User"`).
    #[serde(rename = "type")]
    pub ty: String,
    /// The raw, un-escaped entity id.
    pub id: String,
}

/// One entity supplied to a decision: its identity plus the attributes and
/// direct parents a policy may read (`principal.dept`, `principal in Group`).
#[derive(Debug, Clone, Deserialize, tsify_next::Tsify)]
pub struct EntityInput {
    /// Entity type, namespace included (`"Drupe::User"`).
    #[serde(rename = "type")]
    pub ty: String,
    /// The raw, un-escaped entity id.
    pub id: String,
    /// Attributes, `name -> value`. Validated against the action schema at
    /// decision time, so a wrong-typed attribute fails closed.
    #[serde(default)]
    #[tsify(optional, type = "Record<string, DogwoodValue>")]
    pub attrs: BTreeMap<String, serde_json::Value>,
    /// **Direct** parents (`memberOf` edges). Cedar computes the transitive
    /// closure, so only direct parents are supplied.
    #[serde(default)]
    #[tsify(optional)]
    pub parents: Vec<EntityRef>,
}

/// One event fed to a [`DogwoodAuthorizer`] — the JS analog of the frontend's
/// `Event`, and a mirror of the `.log` wire format's components.
#[derive(Debug, Clone, Deserialize, tsify_next::Tsify)]
#[tsify(from_wasm_abi)]
pub struct EventInput {
    /// The qualified Cedar action id — `"Drupe::Action::Read"`, or a bare
    /// `"Read"`. Split on the **last** `::`, so an action id containing an
    /// interior `::` is not supported (Cedar permits it; Dogwood's own
    /// `Event::builder` has the same restriction).
    pub action: String,
    /// The event kind. `"request"` (the default) is a decision point;
    /// `"response"` / `"error"` are history-only — they update temporal state
    /// and return `undefined`. Which kinds decide is set by the event schema.
    #[serde(default = "default_kind")]
    #[tsify(optional)]
    pub kind: String,
    /// Wall-clock timestamp, in **seconds** — the unit the temporal windows are
    /// defined in (`1h` is 3600). From JS that means
    /// `Math.floor(Date.now() / 1000)`, *not* `Date.now()`: passing
    /// milliseconds silently inflates every window by 1000×, so a `within 1h`
    /// predicate would match only events from the last 3.6 seconds.
    ///
    /// Timestamps order events for the temporal operators, so this must be
    /// **non-decreasing** across calls on one instance.
    #[serde(default)]
    #[tsify(optional)]
    pub timestamp: i64,
    /// The request principal. Setting it makes the event request-wrapping.
    #[serde(default)]
    #[tsify(optional)]
    pub principal: Option<EntityRef>,
    /// The request resource. Setting it makes the event request-wrapping.
    #[serde(default)]
    #[tsify(optional)]
    pub resource: Option<EntityRef>,
    /// The **durable temporal record**: `group -> { name -> value }`, read by
    /// temporal predicates in later events. Distinct from
    /// [`context`](Self::context) — see the module docs.
    #[serde(default)]
    #[tsify(optional, type = "Record<string, Record<string, DogwoodValue>>")]
    pub logged: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// The **per-decision Cedar request context**: `group -> { name -> value }`,
    /// read by a policy as `context.<group>.<name>`. Never persisted.
    #[serde(default)]
    #[tsify(optional, type = "Record<string, Record<string, DogwoodValue>>")]
    pub context: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// The entity store for this decision — attributes and hierarchy for any
    /// entity the policy names.
    #[serde(default)]
    #[tsify(optional)]
    pub entities: Vec<EntityInput>,
}

fn default_kind() -> String {
    "request".to_string()
}

// ─── decision output ─────────────────────────────────────────────────

/// The decision for one event: the verdict plus why.
#[derive(Debug, Clone, Serialize, tsify_next::Tsify)]
#[tsify(into_wasm_abi)]
pub struct AuthorizerDecision {
    /// 0-based index of this decision in the authorizer's decision stream
    /// (history-only events do not advance it).
    pub index: usize,
    /// The event's timestamp, echoed back.
    pub timestamp: i64,
    pub verdict: Verdict,
    /// `true` exactly when `verdict === "allow"` — the convenience Dogwood's
    /// own `Response::allowed` exposes.
    pub allowed: bool,
    /// The `.dw` rule indices that determined the decision. Empty for an
    /// implicit deny (no rule matched).
    pub determining_rules: Vec<usize>,
    /// Evaluation errors folded into this decision. A fail-closed deny carries
    /// its cause here, so a non-empty `errors` on a deny means *something went
    /// wrong*, not *policy said no*.
    pub errors: Vec<String>,
}

// ─── value conversion ────────────────────────────────────────────────

/// Convert a deserialized JS value into a Dogwood [`Value`].
///
/// Integers stay integers; a non-integral number becomes a [`Value::Decimal`]
/// carrying the number's **own** text (not a re-formatted one), so a decimal
/// round-trips as authored wherever JSON preserves it. The two tagged object
/// forms are checked before the plain-record case.
fn to_value(json: &serde_json::Value) -> Result<Value, String> {
    Ok(match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            // Not an i64: either fractional or out of range. Cedar's decimal
            // is text-defined, so keep serde's rendering verbatim and only
            // ensure it *looks* like a decimal.
            None => {
                let mut text = n.to_string();
                if !text.contains('.') {
                    text.push_str(".0");
                }
                Value::Decimal(text)
            }
        },
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(to_value).collect::<Result<_, _>>()?)
        }
        serde_json::Value::Object(map) => {
            // `{ __entity: { type, id } }` — a structured entity reference.
            if let Some(entity) = map.get("__entity") {
                if map.len() != 1 {
                    return Err("`__entity` must be the only key of its object".to_string());
                }
                let obj = entity
                    .as_object()
                    .ok_or("`__entity` must be an object `{ type, id }`")?;
                let ty = obj
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("`__entity` is missing a string `type`")?;
                let id = obj
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("`__entity` is missing a string `id`")?;
                return Ok(Value::Entity {
                    ty: ty.to_string(),
                    id: id.to_string(),
                });
            }
            // `{ __decimal: "1.50" }` — exact decimal text.
            if let Some(decimal) = map.get("__decimal") {
                if map.len() != 1 {
                    return Err("`__decimal` must be the only key of its object".to_string());
                }
                let text = decimal
                    .as_str()
                    .ok_or("`__decimal` must be a string, e.g. `\"1.50\"`")?;
                return Ok(Value::Decimal(text.to_string()));
            }
            Value::Object(
                map.iter()
                    .map(|(k, v)| to_value(v).map(|v| (k.clone(), v)))
                    .collect::<Result<BTreeMap<_, _>, _>>()?,
            )
        }
    })
}

/// Build a frontend [`Event`] from the JS input.
///
/// Every entity reference goes through a structured `*_for` builder method, so
/// ids are escaped canonically exactly once at the Cedar boundary.
fn build_event(input: &EventInput) -> Result<Event, String> {
    let mut builder: EventBuilder =
        Event::builder(&input.action, &input.kind).timestamp(input.timestamp);

    if let Some(p) = &input.principal {
        builder = builder.principal_for(&p.ty, &p.id);
    }
    if let Some(r) = &input.resource {
        builder = builder.resource_for(&r.ty, &r.id);
    }

    for (group, fields) in &input.logged {
        for (name, value) in fields {
            builder = builder.field(group, name, to_value(value)?);
        }
    }
    for (group, fields) in &input.context {
        for (name, value) in fields {
            builder = builder.request_context(group, name, to_value(value)?);
        }
    }

    for entity in &input.entities {
        // `entity_for` merges on repeat, so attributes and parents for the
        // same (ty, id) compose across the two calls.
        let attrs = entity
            .attrs
            .iter()
            .map(|(name, value)| to_value(value).map(|v| (name.as_str(), v)))
            .collect::<Result<Vec<_>, _>>()?;
        builder = builder.entity_for(&entity.ty, &entity.id, attrs);

        if !entity.parents.is_empty() {
            let parents: Vec<(&str, &str)> = entity
                .parents
                .iter()
                .map(|p| (p.ty.as_str(), p.id.as_str()))
                .collect();
            builder = builder.parents_for(&entity.ty, &entity.id, parents);
        }
    }

    Ok(builder.build())
}

// ─── the exported class ──────────────────────────────────────────────

/// A **stateful, live** Dogwood authorizer: lower a policy set once, then feed
/// events as they happen and get a decision per event, with temporal history
/// accumulating across calls.
///
/// This is the counterpart to the one-shot [`replay`](crate::replay): same
/// engine and same lowering, but the caller drives the loop. Because it holds
/// temporal state, one instance corresponds to one history — see
/// [`reset`](DogwoodAuthorizer::reset).
#[wasm_bindgen]
pub struct DogwoodAuthorizer {
    authorizer: Authorizer,
    /// The sources, kept so [`reset`](Self::reset) can re-lower: an
    /// `Authorizer` consumes its `LoweredPolicySet` and the lowered set is not
    /// cloneable, so a fresh history means lowering again.
    source: String,
    action_schema: String,
    event_schema: Option<String>,
    providers: Option<String>,
    macros: Option<String>,
    /// Decision counter — the `index` of the next decision. History-only
    /// events do not advance it.
    decisions: usize,
}

#[wasm_bindgen]
impl DogwoodAuthorizer {
    /// Lower `source` against `actionSchema` and build a fresh authorizer with
    /// empty temporal history. Throws a `DogwoodError` (with `.diagnostic`) on
    /// a parse, macro, lowering, or schema failure — the same error contract as
    /// every other operation in these bindings.
    ///
    /// The trailing arguments are the optional service-schema overrides
    /// (event-schema DSL text, `providers.json` text, macro-library text);
    /// omit them for the defaults.
    #[wasm_bindgen(constructor)]
    pub fn new(
        source: &str,
        action_schema: &str,
        event_schema: Option<String>,
        providers: Option<String>,
        macros: Option<String>,
    ) -> Result<DogwoodAuthorizer, JsValue> {
        let inputs = SchemaInputs {
            event_schema: event_schema.as_deref(),
            providers: providers.as_deref(),
            macros: macros.as_deref(),
        };
        let lowered = lower_for_authorizer(source, &inputs, action_schema).map_err(crate::throw)?;
        Ok(DogwoodAuthorizer {
            authorizer: Authorizer::new(lowered),
            source: source.to_string(),
            action_schema: action_schema.to_string(),
            event_schema,
            providers,
            macros,
            decisions: 0,
        })
    }

    /// Authorize one event.
    ///
    /// Returns the [`AuthorizerDecision`] for a decision-kind event (by
    /// default, `kind: "request"`), or `undefined` for a history-only event —
    /// which still updates temporal history, and is how a host records the
    /// `response` half of a call so later policies can correlate against it.
    ///
    /// Throws a plain `Error` if the event itself is malformed (a bad
    /// `__entity` tag, say). A *policy* problem is never thrown: an evaluation
    /// failure comes back as a fail-closed `deny` with the cause in
    /// [`errors`](AuthorizerDecision::errors).
    #[wasm_bindgen(js_name = isAuthorized)]
    pub fn is_authorized(&mut self, event: EventInput) -> Result<Option<AuthorizerDecision>, JsValue> {
        let built = build_event(&event).map_err(|e| crate::throw(OpError::message(e)))?;

        // `None` is a history-only event: temporal state advanced, no verdict.
        let Some(response) = self.authorizer.is_authorized(&built) else {
            return Ok(None);
        };

        let verdict = match response.decision() {
            Decision::Allow => Verdict::Allow,
            Decision::Deny => Verdict::Deny,
        };
        let decision = AuthorizerDecision {
            index: self.decisions,
            timestamp: event.timestamp,
            verdict,
            allowed: response.allowed(),
            determining_rules: response
                .diagnostics()
                .reason()
                .map(|r| r.rule_index)
                .collect(),
            errors: response.diagnostics().errors().map(str::to_string).collect(),
        };
        self.decisions += 1;
        Ok(Some(decision))
    }

    /// Drop all accumulated temporal history and start over, re-lowering the
    /// original sources. Cheaper than constructing a new instance only in that
    /// the caller need not keep the sources around; the lowering cost is the
    /// same. The decision index restarts at 0.
    pub fn reset(&mut self) -> Result<(), JsValue> {
        let inputs = SchemaInputs {
            event_schema: self.event_schema.as_deref(),
            providers: self.providers.as_deref(),
            macros: self.macros.as_deref(),
        };
        let lowered = lower_for_authorizer(&self.source, &inputs, &self.action_schema)
            .map_err(crate::throw)?;
        self.authorizer = Authorizer::new(lowered);
        self.decisions = 0;
        Ok(())
    }

    /// How many decisions this instance has returned — the `index` the next
    /// decision will carry.
    #[wasm_bindgen(getter, js_name = decisionCount)]
    pub fn decision_count(&self) -> usize {
        self.decisions
    }
}
