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

use std::collections::BTreeSet;

use dogwood_language::{
    Authorizer, Decision, Event, EventBuilder, LoweredPolicySet, Value,
};
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
    /// The **fully qualified** Cedar action id — `"Drupe::Action::Read"`.
    /// Split on the **last** `::`, so an action id containing an interior `::`
    /// is not supported (Cedar permits it; Dogwood's own `Event::builder` has
    /// the same restriction).
    ///
    /// Must name an action the schema declares — see
    /// [`actions`](DogwoodAuthorizer::actions). A *bare* id (`"Read"`) would
    /// otherwise parse and then not resolve, denying with an empty
    /// [`errors`](AuthorizerDecision::errors) and so being indistinguishable
    /// from "policy said no"; it is rejected instead, with the qualified id
    /// suggested.
    pub action: String,
    /// The event kind. `"request"` (the default) is a decision point;
    /// `"response"` / `"error"` are history-only — they update temporal state
    /// and return `undefined`. Which kinds exist, and which decide, is set by
    /// the event schema — see [`eventKinds`](DogwoodAuthorizer::event_kinds) and
    /// [`decisionKinds`](DogwoodAuthorizer::decision_kinds).
    ///
    /// A kind the schema does not declare is **rejected**. Left to the engine it
    /// would be treated as history-only, so a typo (`"requst"`) would silently
    /// yield no decision forever instead of failing loudly.
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
    /// **non-decreasing** across calls on one instance — one instance is one
    /// ordered history. A timestamp before the previous event's is rejected
    /// rather than silently producing wrong temporal answers; see
    /// [`lastTimestamp`](DogwoodAuthorizer::last_timestamp).
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

// ─── the event surface an instance accepts ───────────────────────────

/// The `(action, kind)` surface a lowered policy set derives — what an inbound
/// event is checked against.
///
/// Both halves are silent when got wrong: an action id that does not resolve and
/// a kind the schema never declared each produce a plain `deny` / `undefined`
/// rather than a complaint. Capturing the surface at lowering time lets
/// [`DogwoodAuthorizer::is_authorized`] reject them up front instead.
struct EventSurface {
    /// Every **fully qualified** action id (`"Drupe::Action::Read"`).
    actions: BTreeSet<String>,
    /// Every declared event kind, decision points and history-only alike.
    kinds: BTreeSet<String>,
    /// The subset of [`kinds`](Self::kinds) that are decision points, in the
    /// schema's own order.
    decision_kinds: Vec<String>,
}

impl EventSurface {
    /// Read the surface off a lowered set. `event_signatures` yields one entry
    /// per derived `(action, kind)`; the qualified id is the signature's
    /// namespace (which already carries the trailing `Action` segment) joined
    /// onto its action id.
    fn of(lowered: &LoweredPolicySet) -> EventSurface {
        let mut actions = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        for sig in lowered.event_signatures() {
            let mut qualified = String::new();
            for segment in sig.namespace() {
                qualified.push_str(segment);
                qualified.push_str("::");
            }
            qualified.push_str(sig.action());
            actions.insert(qualified);
            kinds.insert(sig.kind().to_string());
        }
        EventSurface {
            actions,
            kinds,
            decision_kinds: lowered.decision_kinds().map(str::to_string).collect(),
        }
    }
}

/// Render a set for an error message, capped so a schema with a hundred actions
/// does not produce a hundred-line error.
fn listing(items: &BTreeSet<String>) -> String {
    const CAP: usize = 8;
    let shown = items
        .iter()
        .take(CAP)
        .map(|s| format!("`{s}`"))
        .collect::<Vec<_>>()
        .join(", ");
    match items.len().checked_sub(CAP) {
        Some(rest) if rest > 0 => format!("{shown} (and {rest} more)"),
        _ => shown,
    }
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
    /// The `(action, kind)` surface this instance accepts, captured at lowering
    /// time so inbound events can be checked against it.
    surface: EventSurface,
    /// The timestamp of the most recent event observed, or `None` before the
    /// first. Kept to enforce the non-decreasing-timestamp contract, which the
    /// temporal operators depend on and the engine does not check.
    last_timestamp: Option<i64>,
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
        // Reject provider declarations that cannot work in wasm before lowering,
        // so an unresolvable `scriptFile` is a construction-time error rather
        // than a fail-closed deny on every later decision.
        if let Some(json) = providers.as_deref() {
            crate::providers::parse_declarations(json).map_err(crate::throw)?;
        }
        let inputs = SchemaInputs {
            event_schema: event_schema.as_deref(),
            providers: providers.as_deref(),
            macros: macros.as_deref(),
        };
        let lowered = lower_for_authorizer(source, &inputs, action_schema).map_err(crate::throw)?;
        // Read off before the lowered set is moved into the authorizer, which
        // consumes it.
        let surface = EventSurface::of(&lowered);
        Ok(DogwoodAuthorizer {
            authorizer: Authorizer::new(lowered),
            source: source.to_string(),
            action_schema: action_schema.to_string(),
            event_schema,
            providers,
            macros,
            decisions: 0,
            surface,
            last_timestamp: None,
        })
    }

    /// Check an inbound event against what this instance can actually decide:
    /// its action and kind must be ones the schema derives, and its timestamp
    /// must not go backwards.
    ///
    /// All three are checked **before** the event is observed, so a rejected
    /// event leaves the temporal history untouched — a failed call is a no-op,
    /// not a partial one.
    fn check(&self, event: &EventInput) -> Result<(), String> {
        if !self.surface.actions.contains(&event.action) {
            // An id whose last segment matches exactly one known action is
            // almost always a missing namespace — the bare-`"Read"` mistake.
            let tail = event.action.rsplit("::").next().unwrap_or(&event.action);
            let mut same_tail = self
                .surface
                .actions
                .iter()
                .filter(|known| known.rsplit("::").next() == Some(tail));
            let hint = match (same_tail.next(), same_tail.next()) {
                (Some(only), None) => format!(" — did you mean `{only}`?"),
                _ => String::new(),
            };
            return Err(format!(
                "unknown action `{}`: not declared by the action schema, which declares {}. \
                 Action ids are fully qualified, `Ns::Action::Id`{}",
                event.action,
                listing(&self.surface.actions),
                hint,
            ));
        }

        if !self.surface.kinds.contains(&event.kind) {
            return Err(format!(
                "unknown event kind `{}`. The event schema declares {} — of which {} \
                 {} a decision point",
                event.kind,
                listing(&self.surface.kinds),
                listing(&self.surface.decision_kinds.iter().cloned().collect()),
                if self.surface.decision_kinds.len() == 1 { "is" } else { "are" },
            ));
        }

        if self.last_timestamp.is_some_and(|last| event.timestamp < last) {
            let last = self.last_timestamp.unwrap_or_default();
            return Err(format!(
                "event timestamp {} is before the previous event's {}. Timestamps order \
                 events for the temporal operators, so they must be non-decreasing across \
                 calls on one authorizer — one instance is one ordered history. Feed events \
                 in order, or use a separate instance (or `reset()`) per history.",
                event.timestamp, last,
            ));
        }

        Ok(())
    }

    /// Authorize one event.
    ///
    /// Returns the [`AuthorizerDecision`] for a decision-kind event (by
    /// default, `kind: "request"`), or `undefined` for a history-only event —
    /// which still updates temporal history, and is how a host records the
    /// `response` half of a call so later policies can correlate against it.
    ///
    /// Throws a `DogwoodError` if the event is malformed (a missing `action`, a
    /// bad `__entity` tag, a wrong-typed field) or **rejected** by
    /// [`check`](Self::check) — an action or kind the schema does not declare, or
    /// a timestamp before the previous event's. Either way the instance is left
    /// **usable** and the temporal history untouched: the event is validated
    /// before it is observed, so a failed call is a no-op and the next call
    /// decides normally.
    ///
    /// A *policy* problem is never thrown: an evaluation failure comes back as a
    /// fail-closed `deny` with the cause in
    /// [`errors`](AuthorizerDecision::errors).
    ///
    /// The parameter is taken as a `JsValue` and deserialized here rather than
    /// declared as `EventInput` directly, which is load-bearing: wasm-bindgen
    /// acquires the `&mut self` borrow *before* converting arguments, so a
    /// conversion that fails propagates the exception without releasing the
    /// borrow — permanently poisoning the instance (every later call, `free()`
    /// included, then fails with "recursive use of an object"). Converting
    /// inside the body means the failure is an ordinary `Err` return and the
    /// borrow is released. `unchecked_param_type` keeps the TypeScript
    /// signature `EventInput`.
    #[wasm_bindgen(js_name = isAuthorized)]
    pub fn is_authorized(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "EventInput")] event: JsValue,
    ) -> Result<Option<AuthorizerDecision>, JsValue> {
        let event: EventInput = serde_wasm_bindgen::from_value(event)
            .map_err(|e| crate::throw(OpError::message(format!("invalid event: {e}"))))?;
        self.check(&event)
            .map_err(|e| crate::throw(OpError::message(e)))?;
        let built = build_event(&event).map_err(|e| crate::throw(OpError::message(e)))?;

        // Every rejection is behind us, so the event is definitely about to be
        // observed; record its timestamp for the ordering check on the next call.
        // History-only events count — they enter the same ordered history.
        self.last_timestamp = Some(event.timestamp);

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
        self.surface = EventSurface::of(&lowered);
        self.authorizer = Authorizer::new(lowered);
        self.decisions = 0;
        // A fresh history is a fresh ordering: the next event may carry any
        // timestamp, including one before the last event of the old history.
        self.last_timestamp = None;
        Ok(())
    }

    /// How many decisions this instance has returned — the `index` the next
    /// decision will carry.
    #[wasm_bindgen(getter, js_name = decisionCount)]
    pub fn decision_count(&self) -> usize {
        self.decisions
    }

    /// The event kinds that are decision points under this instance's event
    /// schema (`["request"]` by default) — the kinds for which
    /// [`isAuthorized`](Self::is_authorized) returns a decision rather than
    /// `undefined`.
    ///
    /// A kind in [`eventKinds`](Self::event_kinds) but not here is history-only:
    /// it is accepted, it updates temporal state, and it yields no verdict.
    #[wasm_bindgen(getter, js_name = decisionKinds)]
    pub fn decision_kinds(&self) -> Vec<String> {
        self.surface.decision_kinds.clone()
    }

    /// Every event kind this instance's event schema declares, decision points
    /// and history-only alike (`["error", "request", "response"]` by default).
    /// Any other kind is rejected — see [`isAuthorized`](Self::is_authorized).
    #[wasm_bindgen(getter, js_name = eventKinds)]
    pub fn event_kinds(&self) -> Vec<String> {
        self.surface.kinds.iter().cloned().collect()
    }

    /// Every **fully qualified** action id this instance can decide
    /// (`["Drupe::Action::Read", …]`) — the actions the action schema declares.
    /// An event naming anything else is rejected, so a host that maps its own
    /// operation names onto Cedar actions can check the mapping against this
    /// once at startup rather than discovering a gap one denied request at a
    /// time.
    #[wasm_bindgen(getter)]
    pub fn actions(&self) -> Vec<String> {
        self.surface.actions.iter().cloned().collect()
    }

    /// The timestamp of the most recent event observed, or `undefined` before
    /// the first (and after a [`reset`](Self::reset)). The next event's
    /// timestamp must be at least this.
    ///
    /// Widened to `f64` so the TypeScript type is `number`, matching
    /// [`AuthorizerDecision::timestamp`] and the `timestamp` a host passes in.
    /// An `i64` would come back a `BigInt`, which compares false against every
    /// plain number it is likely to be compared with (`5n == 5` is true but
    /// `5n === 5` is false, and mixed arithmetic throws) — a needless trap on a
    /// value that is a count of seconds and so nowhere near `f64`'s exact-integer
    /// limit.
    #[wasm_bindgen(getter, js_name = lastTimestamp)]
    pub fn last_timestamp(&self) -> Option<f64> {
        self.last_timestamp.map(|t| t as f64)
    }
}
