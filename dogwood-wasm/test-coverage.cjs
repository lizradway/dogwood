// Surface-coverage suite: every exported function, every report field, every
// optional argument, every error path, and every value-conversion branch.
//
// `test.cjs` smoke-tests the happy path and `test-live.cjs` pins the live
// authorizer's semantics against `replay`. This file exists to answer a
// different question — "is any part of the binding surface unexercised?" — so it
// is organised by API surface rather than by scenario, and it deliberately
// asserts the *unhappy* paths: what each function does with malformed input,
// and which mistakes fail silently rather than loudly.
//
// The three optional service-schema arguments (`eventSchema`, `providers`,
// `macros`) get load-bearing tests: each is exercised with a pair of calls that
// differ ONLY in that argument and must produce different results. An override
// that was silently ignored would pass a single-call test.
const dw = require("./pkg/dogwood_wasm.js");

let pass = 0,
  fail = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL ${name}: ${e && e.message ? e.message : e}`);
    fail++;
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}
/** Assert that `fn` throws, and return the thrown error for further checks. */
function throws(fn, msg) {
  let threw = null;
  try {
    fn();
  } catch (e) {
    threw = e;
  }
  assert(threw !== null, msg || "expected a throw, got none");
  return threw;
}

// ─── fixtures ────────────────────────────────────────────────────────
//
// The action schema mirrors the frontend's own provider_only corpus schema, so
// the provider cases below are the corpus's cases and their expected verdicts
// are the corpus's expected verdicts.
const SCHEMA = `namespace Drupe {
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  type ReadInput = { document: String };
  type ReadOutput = { content: String };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, output: ReadOutput }
  };
}`;

const ALLOW_ALL = `permit(principal, action == Drupe::Action::"Read", resource);`;

const PRINCIPAL = { type: "Drupe::OAuthUser", id: "alice" };
const RESOURCE = { type: "Drupe::Gateway", id: "gw1" };

/** A decision-kind event, with `input` in both datasets. */
function event(ts, extra = {}) {
  const input = { document: "d" };
  return {
    action: "Drupe::Action::Read",
    kind: "request",
    timestamp: ts,
    principal: PRINCIPAL,
    resource: RESOURCE,
    logged: { input },
    context: { input },
    ...extra,
  };
}

// Event schemas taken verbatim in shape from
// `dogwood-language/configuration/event-schemas/`.
const CUSTOM_KINDS = `
decision event <A>::attempt {
    ...inputs(A),
    actor: principalType(A),
}
event <A>::outcome {
    ...inputs(A),
    ...outputs(A),
    actor: principalType(A),
}`;

const WIDE_WINDOW_SCHEMA = `max_window = 7d
decision event <A>::request {
    ...inputs(A),
    callerPrincipal: principalType(A),
    callerResource:  resourceType(A),
    requestId:       String,
}
event <A>::response {
    ...inputs(A),
    ...outputs(A),
    callerPrincipal: principalType(A),
    callerResource:  resourceType(A),
    requestId:       String,
}`;

// An information provider with its Rhai script INLINE. `scriptFile` cannot work
// here — see the dedicated test below.
const RHAI_SCRIPT = `fn evaluate(text, pattern) {
  if type_of(text) == "()" || type_of(pattern) == "()" { return #{ matched: false }; }
  #{ matched: regex_is_match(pattern, text) }
}`;
function providersJson(implementation) {
  return JSON.stringify({
    availableProviders: {
      "Strings::Matches": {
        argumentTypes: [{ paramType: "string" }, { paramType: "string" }],
        outputType: {
          paramType: "record",
          fields: { matched: { paramType: "bool" } },
          required: ["matched"],
        },
        implementation,
      },
    },
  });
}
const PROVIDERS_INLINE = providersJson({ kind: "rhai", script: RHAI_SCRIPT });
const PROVIDERS_SCRIPTFILE = providersJson({ kind: "rhai", scriptFile: "matches.rhai" });

const GUARDRAIL_POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when guardrails { Strings::Matches(context.input.document, "^[A-Z]+$").matched == true };`;

const MACROS = `def temporal seen_within(?w) {
    formerly within ?w Drupe::Action::"Read"::response{}
};`;
const MACRO_POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { seen_within(1h) };`;

/** A `.log` line for the Read action. */
function traceLine(ts, doc) {
  const d = JSON.stringify(doc);
  return (
    `@${ts} scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") ` +
    `request_context(input: { document: ${d} }) ` +
    `Drupe::Action::"Read"::request(callerPrincipal: Drupe::OAuthUser::"alice", ` +
    `input: { document: ${d} })`
  );
}

console.log("Dogwood binding surface-coverage tests\n");

// ═══ 1. checkParse ═══════════════════════════════════════════════════
console.log("checkParse");

check("reports policy_count over a multi-policy set", () => {
  const r = dw.checkParse(`${ALLOW_ALL}\nforbid(principal, action, resource);`);
  assert(r.policy_count === 2, "policy_count, got " + r.policy_count);
  assert(r.policies.length === 2, "one summary per policy");
});

check("summarizes every PolicySummary field", () => {
  const r = dw.checkParse(GUARDRAIL_POLICY);
  const p = r.policies[0];
  // All four fields, each with a meaningful value rather than just "defined".
  assert(p.temporal_count === 0, "temporal_count on a non-temporal policy");
  assert(p.uses_temporal === false, "uses_temporal");
  assert(
    JSON.stringify(p.provider_invocations) === JSON.stringify(["Strings::Matches"]),
    "provider_invocations, got " + JSON.stringify(p.provider_invocations),
  );
  assert(
    JSON.stringify(p.undeclared_providers) === JSON.stringify(["Strings::Matches"]),
    "an undeclared provider is reported, got " + JSON.stringify(p.undeclared_providers),
  );
});

check("counts multiple temporal leaves", () => {
  const two = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 1h Drupe::Action::"Read"::response{} }
when temporal { formerly within 2h Drupe::Action::"Read"::response{} };`;
  const p = dw.checkParse(two).policies[0];
  assert(p.uses_temporal === true, "uses_temporal");
  assert(p.temporal_count === 2, "temporal_count, got " + p.temporal_count);
});

// LOAD-BEARING: the `providers` override must reach check_parse. These two calls
// differ only in that argument; if it were dropped, both would report the
// provider as undeclared and this test would fail.
check("the providers override is wired (undeclared_providers clears)", () => {
  const without = dw.checkParse(GUARDRAIL_POLICY).policies[0];
  const withDecl = dw.checkParse(GUARDRAIL_POLICY, undefined, PROVIDERS_INLINE).policies[0];
  assert(without.undeclared_providers.length === 1, "undeclared without the override");
  assert(
    withDecl.undeclared_providers.length === 0,
    "declared WITH the override, got " + JSON.stringify(withDecl.undeclared_providers),
  );
  // The invocation itself is reported either way — only declaredness changes.
  assert(withDecl.provider_invocations.length === 1, "invocation still reported");
});

check("throws DogwoodError on a syntax error, with byte offsets into the source", () => {
  const src = "permit(principal action resource);";
  const e = throws(() => dw.checkParse(src));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(e.diagnostic.severity === "error", "severity");
  assert(typeof e.diagnostic.message === "string" && e.diagnostic.message.length > 0, "message");
  assert(Array.isArray(e.diagnostic.labels) && e.diagnostic.labels.length > 0, "labels present");
  const l = e.diagnostic.labels[0];
  // The contract is that offsets index the string that was passed in.
  assert(
    l.start >= 0 && l.start + l.len <= src.length,
    `label ${l.start}..${l.start + l.len} must fall inside the ${src.length}-byte source`,
  );
});

check("throws on an unknown macro (no default def)", () => {
  const e = throws(() => dw.checkParse(MACRO_POLICY));
  assert(/seen_within/.test(e.message), "message names the macro, got " + e.message);
});

// ═══ 2. validate ═════════════════════════════════════════════════════
console.log("\nvalidate");

check("passes a well-typed policy, with all four fields set", () => {
  const r = dw.validate(ALLOW_ALL, SCHEMA);
  assert(r.passed === true, "passed, errors: " + JSON.stringify(r.errors));
  assert(r.passed_without_warnings === true, "passed_without_warnings");
  assert(Array.isArray(r.errors) && r.errors.length === 0, "errors empty");
  assert(Array.isArray(r.warnings) && r.warnings.length === 0, "warnings empty");
});

check("returns (does not throw) a type error, with a full Diagnostic", () => {
  const src = `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.nope == "x" };`;
  const r = dw.validate(src, SCHEMA);
  assert(r.passed === false, "a bad attribute must fail validation");
  assert(r.passed_without_warnings === false, "passed_without_warnings");
  assert(r.errors.length >= 1, "an error is reported");
  const d = r.errors[0];
  assert(d.severity === "error", "severity, got " + d.severity);
  assert(typeof d.code === "string", "code present, got " + d.code);
  assert(/nope/.test(d.message), "message names the bad attribute, got " + d.message);
  assert(d.labels.length >= 1 && typeof d.labels[0].start === "number", "labels carry offsets");
  assert(
    d.labels[0].start + d.labels[0].len <= src.length,
    "offsets index the .dw source that was passed in",
  );
  assert(typeof d.help === "string" && d.help.length > 0, "help text present");
  assert(d.spanned === true, "spanned");
});

// LOAD-BEARING: the `eventSchema` override must reach lowering. The SAME policy
// validates differently under the two schemas — the only difference is the
// `max_window` cap — so an ignored override could not produce both results.
check("the eventSchema override is wired (max_window gates the same policy)", () => {
  const wide = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 7d Drupe::Action::"Read"::response{} };`;
  const underDefault = dw.validate(wide, SCHEMA);
  assert(
    underDefault.passed === false,
    "`within 7d` must exceed the default 24h cap",
  );
  assert(
    /max_window|24h/.test(underDefault.errors[0].message),
    "the error explains the cap, got " + underDefault.errors[0].message,
  );
  const underWide = dw.validate(wide, SCHEMA, WIDE_WINDOW_SCHEMA);
  assert(
    underWide.passed === true,
    "raising max_window to 7d must admit it, errors: " + JSON.stringify(underWide.errors),
  );
});

// LOAD-BEARING: the `macros` override must reach parsing.
check("the macros override is wired (a custom def resolves)", () => {
  throws(() => dw.validate(MACRO_POLICY, SCHEMA), "unknown macro must throw without the library");
  const r = dw.validate(MACRO_POLICY, SCHEMA, undefined, undefined, MACROS);
  assert(r.passed === true, "with the library it validates, errors: " + JSON.stringify(r.errors));
});

check("throws (not returns) on a fatal parse error", () => {
  const e = throws(() => dw.validate("permit(", SCHEMA));
  assert(e.name === "DogwoodError", "name, got " + e.name);
});

check("a bad action schema throws, with offsets into the SCHEMA text", () => {
  const badSchema = "namespace Drupe { entity User";
  const e = throws(() => dw.validate(ALLOW_ALL, badSchema));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  if (e.diagnostic.labels && e.diagnostic.labels.length > 0) {
    const l = e.diagnostic.labels[0];
    assert(
      l.start + l.len <= badSchema.length,
      `a schema error's offsets must index the schema (${l.start}..${l.start + l.len} vs ` +
        `${badSchema.length}), not the .dw source`,
    );
  }
});

// ═══ 3. lower ════════════════════════════════════════════════════════
console.log("\nlower");

check("emits every artifact field, and the schema round-trips", () => {
  const a = dw.lower(ALLOW_ALL, SCHEMA);
  assert(a.cedar_policies.includes("permit"), "cedar_policies is Cedar text");
  assert(a.cedar_schema.includes("Drupe"), "cedar_schema is schema text");
  // The augmented schema must itself be a valid Cedar schema.
  assert(dw.checkActionSchema(a.cedar_schema).ok === true, "augmented schema re-checks clean");
  const json = JSON.parse(a.cedar_schema_json); // must not throw
  assert(Object.keys(json).includes("Drupe"), "cedar_schema_json has the namespace");
  assert(a.self_contained === true, "a plain policy is self-contained");
  assert(Array.isArray(a.temporal_fields) && a.temporal_fields.length === 0, "no temporal fields");
  assert(Array.isArray(a.provider_fields) && a.provider_fields.length === 0, "no provider fields");
  assert(
    JSON.stringify(a.decision_kinds) === JSON.stringify(["request"]),
    "decision_kinds defaults to [request], got " + JSON.stringify(a.decision_kinds),
  );
});

check("hoists temporal fields and drops self_contained", () => {
  const t = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 1h Drupe::Action::"Read"::response{} };`;
  const a = dw.lower(t, SCHEMA);
  assert(a.self_contained === false, "temporal needs Dogwood at authorize time");
  assert(a.temporal_fields.length === 1, "one hoisted field, got " + a.temporal_fields.length);
  assert(typeof a.temporal_fields[0] === "string", "field ids are strings");
});

check("hoists provider fields and drops self_contained", () => {
  const a = dw.lower(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_INLINE);
  assert(a.self_contained === false, "a provider policy is not self-contained");
  assert(a.provider_fields.length === 1, "one provider field, got " + JSON.stringify(a.provider_fields));
  assert(a.temporal_fields.length === 0, "and no temporal fields");
});

check("decision_kinds follows the event schema", () => {
  const a = dw.lower(ALLOW_ALL, SCHEMA, CUSTOM_KINDS);
  assert(
    JSON.stringify(a.decision_kinds) === JSON.stringify(["attempt"]),
    "custom-kinds schema decides on `attempt`, got " + JSON.stringify(a.decision_kinds),
  );
});

// ═══ 4. replay ═══════════════════════════════════════════════════════
console.log("\nreplay");

check("returns an empty stream for an empty trace", () => {
  const r = dw.replay(ALLOW_ALL, SCHEMA, "");
  assert(Array.isArray(r.verdicts) && r.verdicts.length === 0, "no verdicts");
});

check("indexes a multi-event trace and fills every TimepointVerdict field", () => {
  const trace = [traceLine(1000, "a"), traceLine(1010, "b")].join("\n");
  const r = dw.replay(ALLOW_ALL, SCHEMA, trace);
  assert(r.verdicts.length === 2, "two decisions, got " + r.verdicts.length);
  r.verdicts.forEach((v, i) => {
    assert(v.index === i, `index ${i}, got ${v.index}`);
    assert(v.verdict === "allow", "verdict");
    assert(Array.isArray(v.errors) && v.errors.length === 0, "no errors");
    assert(Array.isArray(v.determining_rules), "determining_rules is an array");
  });
  assert(r.verdicts[0].timestamp === 1000 && r.verdicts[1].timestamp === 1010, "timestamps");
  assert(r.verdicts[0].determining_rules.length === 1, "an allow names its rule");
});

check("an implicit deny carries no determining rules", () => {
  const r = dw.replay(`forbid(principal, action, resource);`, SCHEMA, traceLine(1000, "a"));
  assert(r.verdicts[0].verdict === "deny", "deny");
  assert(
    r.verdicts[0].determining_rules.length === 1,
    "an explicit forbid names its rule, got " + JSON.stringify(r.verdicts[0].determining_rules),
  );
  const r2 = dw.replay(
    `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.document == "never" };`,
    SCHEMA,
    traceLine(1000, "a"),
  );
  assert(r2.verdicts[0].verdict === "deny", "unmatched permit denies");
  assert(
    r2.verdicts[0].determining_rules.length === 0,
    "an IMPLICIT deny names no rule, got " + JSON.stringify(r2.verdicts[0].determining_rules),
  );
});

check("throws on a malformed trace, with offsets into the LOG text", () => {
  const badLog = "@@@ nonsense";
  const e = throws(() => dw.replay(ALLOW_ALL, SCHEMA, badLog));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(/trace|timestamp/i.test(e.message), "message mentions the trace, got " + e.message);
});

check("providers execute during replay (Rhai runs under wasm)", () => {
  // The frontend's own corpus case 0001: "ABC" matches ^[A-Z]+$, "abc" does not.
  const trace = [traceLine(0, "ABC"), traceLine(10, "abc"), traceLine(20, "AB12")].join("\n");
  const r = dw.replay(GUARDRAIL_POLICY, SCHEMA, trace, undefined, PROVIDERS_INLINE);
  const got = r.verdicts.map((v) => v.verdict).join(",");
  assert(got === "allow,deny,deny", "expected allow,deny,deny — got " + got);
  assert(r.verdicts[0].errors.length === 0, "a working provider reports no errors");
});

// ═══ 5. schema checks ════════════════════════════════════════════════
console.log("\ncheckActionSchema / checkEventSchema / checkProviders");

check("checkActionSchema accepts a valid schema and reports its kind", () => {
  const r = dw.checkActionSchema(SCHEMA);
  assert(r.ok === true, "ok");
  assert(r.kind === "action", "kind, got " + r.kind);
});

check("checkActionSchema throws on a malformed schema", () => {
  const e = throws(() => dw.checkActionSchema("namespace { entity"));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(e.diagnostic.severity === "error", "severity");
});

check("checkEventSchema accepts the default-shaped and custom-kind schemas", () => {
  const r = dw.checkEventSchema(CUSTOM_KINDS);
  assert(r.ok === true, "ok");
  assert(r.kind === "event", "kind, got " + r.kind);
  assert(dw.checkEventSchema(WIDE_WINDOW_SCHEMA).ok === true, "a max_window directive is accepted");
});

check("checkEventSchema throws on a malformed schema", () => {
  const e = throws(() => dw.checkEventSchema("not an event schema"));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(/event schema/i.test(e.message), "message names the artifact, got " + e.message);
});

check("checkProviders accepts a well-formed declarations file", () => {
  const r = dw.checkProviders(PROVIDERS_INLINE);
  assert(r.ok === true, "ok");
  assert(r.kind === "providers", "kind, got " + r.kind);
});

check("checkProviders throws on malformed JSON", () => {
  const e = throws(() => dw.checkProviders("{"));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(/providers/i.test(e.message), "message names the artifact, got " + e.message);
});

check("checkProviders throws on JSON that is not a declarations file", () => {
  throws(() => dw.checkProviders(`{"availableProviders": {"Bad::P": {"nonsense": 1}}}`));
});

// A `scriptFile` reference is structurally valid but unresolvable in wasm (no
// filesystem), so left alone it is a false green: the check reports ok, then the
// provider fails closed on every decision. Rejected up front instead — the whole
// point is that this is caught at check time, not discovered as a mystery deny.
check("checkProviders REJECTS a scriptFile provider (unresolvable in wasm)", () => {
  const e = throws(
    () => dw.checkProviders(PROVIDERS_SCRIPTFILE),
    "a providers file that cannot work here must not report ok",
  );
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(/scriptFile|matches\.rhai/.test(e.message), "names the file, got " + e.message);
  assert(/implementation\.script|inline/i.test(e.message), "says how to fix it, got " + e.message);
  assert(e.message.includes("Strings::Matches"), "names the provider, got " + e.message);
});

// The same guard on every entry point that accepts provider text — otherwise the
// check would reject it and the operation would accept it, which is worse than
// either alone.
check("every providers-taking operation rejects a scriptFile provider", () => {
  const ops = {
    checkProviders: () => dw.checkProviders(PROVIDERS_SCRIPTFILE),
    checkParse: () => dw.checkParse(GUARDRAIL_POLICY, undefined, PROVIDERS_SCRIPTFILE),
    validate: () => dw.validate(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_SCRIPTFILE),
    lower: () => dw.lower(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_SCRIPTFILE),
    replay: () =>
      dw.replay(GUARDRAIL_POLICY, SCHEMA, traceLine(0, "ABC"), undefined, PROVIDERS_SCRIPTFILE),
    "new DogwoodAuthorizer": () =>
      new dw.DogwoodAuthorizer(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_SCRIPTFILE),
  };
  for (const [name, fn] of Object.entries(ops)) {
    const e = throws(fn, `${name} accepted an unresolvable scriptFile`);
    assert(/scriptFile/.test(e.message), `${name} threw for the wrong reason: ${e.message}`);
  }
  // ...and the inline form still works through all of them, so the guard is
  // rejecting the unresolvable case rather than providers in general.
  assert(dw.checkProviders(PROVIDERS_INLINE).ok === true, "inline providers still pass");
  assert(
    dw.validate(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_INLINE).passed === true,
    "inline providers still validate",
  );
});

check("a `rhai` implementation with neither script nor scriptFile is rejected", () => {
  const e = throws(() => dw.checkProviders(providersJson({ kind: "rhai" })));
  assert(/no script|neither/.test(e.message), "explains what is missing, got " + e.message);
});

// ═══ 6. mcpToCedarSchema ═════════════════════════════════════════════
console.log("\nmcpToCedarSchema");

check("generates a schema that is itself valid and usable for lowering", () => {
  const manifest = JSON.stringify([
    {
      name: "SellShares",
      description: "Sell shares of a stock.",
      inputSchema: {
        type: "object",
        properties: { stock: { type: "string" }, shares: { type: "integer" } },
        required: ["stock", "shares"],
      },
    },
  ]);
  const generated = dw.mcpToCedarSchema(manifest);
  assert(generated.includes("SellShares"), "names the action");
  // Not just "is a string": it must round-trip through the schema checker AND
  // actually work as an action schema.
  assert(dw.checkActionSchema(generated).ok === true, "generated schema is valid Cedar");
  const r = dw.validate(
    `permit(principal, action == Drupe::Action::"SellShares", resource)
when { context.input.stock == "ACME" };`,
    generated,
  );
  assert(r.passed === true, "a policy over the generated action validates: " + JSON.stringify(r.errors));
});

check("an empty manifest yields the bare template", () => {
  const s = dw.mcpToCedarSchema("[]");
  assert(typeof s === "string" && s.length > 0, "still returns the template");
  assert(dw.checkActionSchema(s).ok === true, "and it is valid");
});

check("throws on a malformed manifest", () => {
  const e = throws(() => dw.mcpToCedarSchema("{not json"));
  assert(e.name === "DogwoodError", "name, got " + e.name);
  assert(/manifest/i.test(e.message), "message names the manifest, got " + e.message);
});

// ═══ 7. DogwoodAuthorizer — overrides and kinds ══════════════════════
console.log("\nDogwoodAuthorizer: overrides, kinds, lifecycle");

check("providers execute through the live authorizer too", () => {
  const auth = new dw.DogwoodAuthorizer(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_INLINE);
  try {
    const yes = auth.isAuthorized(event(0, { logged: { input: { document: "ABC" } }, context: { input: { document: "ABC" } } }));
    const no = auth.isAuthorized(event(10, { logged: { input: { document: "abc" } }, context: { input: { document: "abc" } } }));
    assert(yes.verdict === "allow", "uppercase allowed, got " + JSON.stringify(yes));
    assert(no.verdict === "deny", "lowercase denied, got " + no.verdict);
    assert(yes.errors.length === 0, "no evaluation errors");
  } finally {
    auth.free();
  }
});

// LOAD-BEARING: a custom event schema must change WHICH KINDS DECIDE. Under
// `custom-kinds`, `attempt` decides and the default `request` does not — so an
// ignored eventSchema argument would invert both assertions.
check("a custom event schema changes which kinds decide", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA, CUSTOM_KINDS);
  try {
    assert(
      JSON.stringify(auth.decisionKinds) === JSON.stringify(["attempt"]),
      "decisionKinds reflects the schema, got " + JSON.stringify(auth.decisionKinds),
    );
    const decided = auth.isAuthorized(event(100, { kind: "attempt" }));
    assert(decided !== undefined && decided.verdict === "allow", "`attempt` decides");
    assert(
      auth.isAuthorized(event(110, { kind: "outcome" })) === undefined,
      "`outcome` is history-only",
    );
    // This schema does not declare `request` at all, so the default kind — which
    // decides under the default schema — is now rejected outright. An ignored
    // eventSchema argument would make this call succeed instead.
    const e = throws(
      () => auth.isAuthorized(event(120, { kind: "request" })),
      "`request` is not a kind under this schema",
    );
    assert(/attempt/.test(e.message), "the message lists this schema's kinds, got " + e.message);
  } finally {
    auth.free();
  }
});

check("the kind getters default correctly and survive reset", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    for (const when of ["initially", "after reset"]) {
      assert(
        JSON.stringify(auth.decisionKinds) === JSON.stringify(["request"]),
        `decisionKinds ${when}, got ` + JSON.stringify(auth.decisionKinds),
      );
      // Every declared kind, not just the deciding ones — the two getters
      // together are what distinguish "history-only" from "not a kind at all".
      assert(
        JSON.stringify(auth.eventKinds) === JSON.stringify(["error", "request", "response"]),
        `eventKinds ${when}, got ` + JSON.stringify(auth.eventKinds),
      );
      auth.reset();
    }
  } finally {
    auth.free();
  }
});

check("eventKinds tracks a custom event schema, and both getters stay consistent", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA, CUSTOM_KINDS);
  try {
    assert(
      JSON.stringify(auth.eventKinds) === JSON.stringify(["attempt", "outcome"]),
      "eventKinds, got " + JSON.stringify(auth.eventKinds),
    );
    // decisionKinds must always be a subset of eventKinds; a kind in the
    // difference is history-only.
    assert(
      auth.decisionKinds.every((k) => auth.eventKinds.includes(k)),
      "decisionKinds must be a subset of eventKinds",
    );
    assert(!auth.eventKinds.includes("request"), "`request` is not declared by this schema");
  } finally {
    auth.free();
  }
});

// Formerly a silent no-op: an undeclared kind was treated as history-only, so a
// typo returned `undefined` forever and nothing was ever authorized. Rejected now.
check("an unrecognized kind is REJECTED, not treated as history-only", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    const e = throws(
      () => auth.isAuthorized(event(100, { kind: "requst" })), // typo
      "a kind the schema never declared must not be silently accepted",
    );
    assert(e.name === "DogwoodError", "name, got " + e.name);
    assert(e.message.includes("requst"), "quotes the bad kind, got " + e.message);
    assert(/request/.test(e.message), "lists the declared kinds, got " + e.message);
    assert(/decision point/.test(e.message), "says which decide, got " + e.message);
    // A genuinely history-only kind is still accepted and still yields no
    // verdict — the rejection must not have swept that case up with it.
    assert(auth.isAuthorized(event(110, { kind: "response" })) === undefined, "response is fine");
    assert(auth.decisionCount === 0, "neither call counted as a decision");
    // The rejected event must not have entered history at all.
    assert(auth.lastTimestamp === 110, "the rejected event left no trace, got " + auth.lastTimestamp);
  } finally {
    auth.free();
  }
});

// Formerly the worst of the silent modes: an unqualified id denied with an EMPTY
// `errors`, indistinguishable from "policy said no".
check("a bare (unqualified) action id is REJECTED, with the qualified id suggested", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    assert(auth.isAuthorized(event(100)).verdict === "allow", "the qualified id allows");
    const e = throws(
      () => auth.isAuthorized(event(110, { action: "Read" })),
      "a bare id must not silently deny",
    );
    assert(e.name === "DogwoodError", "name, got " + e.name);
    assert(
      e.message.includes('did you mean `Drupe::Action::Read`'),
      "the unique tail match is suggested, got " + e.message,
    );
    // An action that is not a suffix of any known one gets no bogus suggestion.
    const f = throws(() => auth.isAuthorized(event(120, { action: "Drupe::Action::Delete" })));
    assert(!/did you mean/.test(f.message), "no spurious suggestion, got " + f.message);
    assert(
      f.message.includes("Drupe::Action::Read"),
      "but the known actions are still listed, got " + f.message,
    );
    // The instance is unharmed by either rejection.
    assert(auth.isAuthorized(event(130)).verdict === "allow", "still decides afterwards");
    assert(auth.decisionCount === 2, "only the two real decisions counted");
  } finally {
    auth.free();
  }
});

// `actions` comes from the ACTION SCHEMA, not from the policy set. That is what
// makes rejecting an unknown action safe: an action no policy mentions is still
// a legal event, and must still get a (deny) decision rather than a throw.
check("actions lists every schema action, including ones no policy names", () => {
  const TWO_ACTIONS = `namespace Drupe {
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  type ReadInput = { document: String };
  type ReadOutput = { content: String };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, output: ReadOutput }
  };
  action "Write" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, output: ReadOutput }
  };
}`;
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, TWO_ACTIONS);
  try {
    assert(
      JSON.stringify(auth.actions) ===
        JSON.stringify(["Drupe::Action::Read", "Drupe::Action::Write"]),
      "both actions listed, got " + JSON.stringify(auth.actions),
    );
    const unpoliced = auth.isAuthorized(event(100, { action: "Drupe::Action::Write" }));
    assert(unpoliced !== undefined, "an unpoliced action still gets a decision, not a throw");
    assert(unpoliced.verdict === "deny", "and it denies, got " + unpoliced.verdict);
    assert(unpoliced.errors.length === 0, "an implicit deny carries no errors");
  } finally {
    auth.free();
  }
});

// Cedar permits an action id containing `::`; `Event::builder` recovers the id by
// splitting on the LAST `::`, so such an action cannot be addressed at all — it
// used to deny with an empty `errors`, the same indistinguishable-from-policy
// failure a bare id gave. Rejected on the same grounds.
check("an action id containing `::` is rejected, not silently un-addressable", () => {
  const INNER = `namespace Drupe {
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  type ReadInput = { document: String };
  type ReadOutput = { content: String };
  action "Read::Extra" appliesTo {
    principal: [OAuthUser], resource: [Gateway],
    context: { input: ReadInput, output: ReadOutput }
  };
}`;
  const auth = new dw.DogwoodAuthorizer(
    `permit(principal, action == Drupe::Action::"Read::Extra", resource);`,
    INNER,
  );
  try {
    // It IS in the schema, so `actions` lists it — the rejection is about the
    // builder's addressing limit, not about the action being unknown.
    assert(
      JSON.stringify(auth.actions) === JSON.stringify(["Drupe::Action::Read::Extra"]),
      "listed in actions, got " + JSON.stringify(auth.actions),
    );
    const e = throws(
      () => auth.isAuthorized(event(1, { action: "Drupe::Action::Read::Extra" })),
      "an un-addressable action must not look like a decision",
    );
    assert(e.name === "DogwoodError", "name, got " + e.name);
    assert(/not supported|last `::`/.test(e.message), "explains why, got " + e.message);
    assert(!/unknown action/.test(e.message), "and does NOT claim it is unknown");
  } finally {
    auth.free();
  }
});

// A schema with no namespace derives `Action::Read`. Pinned because the guard
// builds the qualified id itself, and getting that wrong would reject every
// event under an unnamespaced schema — a false rejection, the failure mode a
// validity check must not have.
check("a namespace-less action schema is not falsely rejected", () => {
  const BARE_SCHEMA = `entity Gateway;
entity OAuthUser = { id: String } tags String;
type ReadInput = { document: String };
type ReadOutput = { content: String };
action "Read" appliesTo {
  principal: [OAuthUser], resource: [Gateway],
  context: { input: ReadInput, output: ReadOutput }
};`;
  const auth = new dw.DogwoodAuthorizer(
    `permit(principal, action == Action::"Read", resource);`,
    BARE_SCHEMA,
  );
  try {
    assert(
      JSON.stringify(auth.actions) === JSON.stringify(["Action::Read"]),
      "qualified id, got " + JSON.stringify(auth.actions),
    );
    const d = auth.isAuthorized({
      action: "Action::Read",
      timestamp: 1,
      principal: { type: "OAuthUser", id: "alice" },
      resource: { type: "Gateway", id: "gw1" },
      logged: { input: { document: "d" } },
      context: { input: { document: "d" } },
    });
    assert(d !== undefined && d.verdict === "allow", "decides, got " + JSON.stringify(d));
  } finally {
    auth.free();
  }
});

check("macros override reaches the live authorizer", () => {
  throws(
    () => new dw.DogwoodAuthorizer(MACRO_POLICY, SCHEMA),
    "an unknown macro must throw from the constructor",
  );
  const auth = new dw.DogwoodAuthorizer(MACRO_POLICY, SCHEMA, undefined, undefined, MACROS);
  try {
    assert(auth.isAuthorized(event(100)) !== undefined, "and with the library it decides");
  } finally {
    auth.free();
  }
});

check("a bad action schema throws from the constructor", () => {
  const e = throws(() => new dw.DogwoodAuthorizer(ALLOW_ALL, "namespace Drupe { entity"));
  assert(e.name === "DogwoodError", "name, got " + e.name);
});

check("a malformed providers.json throws from the constructor", () => {
  throws(() => new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA, undefined, "{"));
});

check("a malformed event schema throws from the constructor", () => {
  throws(() => new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA, "not a schema"));
});

// ═══ 8. value conversion — every branch of to_value ══════════════════
console.log("\nvalue conversion");

check("accepts every JSON value kind plus both tagged escapes", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    const d = auth.isAuthorized(
      event(1, {
        logged: {
          input: { document: "d" },
          edge: {
            nul: null, // Value::Null
            yes: true, // Value::Bool
            no: false,
            zero: 0, // Value::Int
            neg: -42,
            i64ish: 9007199254740991, // largest exact JS integer
            frac: 2.5, // -> Decimal (non-integral number)
            negFrac: -0.125,
            str: "plain", // Value::String
            uni: "héllo → 世界 🎉", // multi-byte, must survive the ABI
            quoted: 'has "quotes" and \\ backslash',
            arr: [1, "two", false, null], // Value::Array, mixed
            emptyArr: [],
            obj: { a: 1, b: { c: "deep" } }, // Value::Object, nested
            emptyObj: {},
            ent: { __entity: { type: "Drupe::OAuthUser", id: "bob" } },
            dec: { __decimal: "1.50" }, // exact text preserved
            deepMix: [{ __decimal: "0.01" }, [{ __entity: { type: "Drupe::Gateway", id: "g" } }]],
          },
        },
      }),
    );
    assert(d.verdict === "allow", "conversion must not disturb the decision: " + JSON.stringify(d));
  } finally {
    auth.free();
  }
});

check("each malformed tagged value throws a naming Error", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    const bad = (v) => () => auth.isAuthorized(event(1, { logged: { e: { x: v } } }));
    // Every error branch in to_value, each asserted to name its tag.
    assert(/__entity/.test(throws(bad({ __entity: { type: "T" } })).message), "missing id");
    assert(/__entity/.test(throws(bad({ __entity: { id: "i" } })).message), "missing type");
    assert(/__entity/.test(throws(bad({ __entity: "nope" })).message), "not an object");
    assert(
      /__entity/.test(throws(bad({ __entity: { type: "T", id: "i" }, extra: 1 })).message),
      "extra sibling key",
    );
    assert(/__decimal/.test(throws(bad({ __decimal: 1.5 })).message), "non-string decimal");
    assert(
      /__decimal/.test(throws(bad({ __decimal: "1.5", extra: 1 })).message),
      "extra sibling key",
    );
    assert(
      /__entity/.test(throws(bad({ __entity: { type: 1, id: "i" } })).message),
      "non-string type",
    );
  } finally {
    auth.free();
  }
});

// An integer must stay a Cedar Long. The conversion goes JS number ->
// serde_json::Value -> Dogwood Value, and if the middle step rendered integers
// as floats they would become Decimals, which a `Long` comparison rejects. This
// test would catch that as a fail-closed deny.
check("an integer attribute stays an integer (not a decimal)", () => {
  const schema = `namespace Drupe {
  entity Gateway;
  entity OAuthUser = { id: String, count: Long } tags String;
  type ReadInput = { document: String };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ReadInput }
  };
}`;
  const policy = `permit(principal, action == Drupe::Action::"Read", resource)
when { principal.count == 3 };`;
  const auth = new dw.DogwoodAuthorizer(policy, schema);
  try {
    const d = auth.isAuthorized(
      event(1, { entities: [{ type: "Drupe::OAuthUser", id: "alice", attrs: { id: "alice", count: 3 } }] }),
    );
    assert(
      d.verdict === "allow",
      "3 must compare equal to the Long 3, got " + JSON.stringify(d),
    );
    const no = auth.isAuthorized(
      event(2, { entities: [{ type: "Drupe::OAuthUser", id: "alice", attrs: { id: "alice", count: 4 } }] }),
    );
    assert(no.verdict === "deny", "and 4 must not, got " + no.verdict);
    assert(no.errors.length === 0, "a plain mismatch is not an evaluation error");
  } finally {
    auth.free();
  }
});

// REGRESSION: an argument that fails to deserialize must not poison the
// instance. wasm-bindgen takes the `&mut self` borrow before converting
// arguments, so a naive `event: EventInput` parameter leaks the borrow on a
// conversion error — after which every method, `free()` included, throws
// "recursive use of an object" and the wasm-heap allocation can never be
// released. `isAuthorized` deserializes inside the body to avoid that.
check("a malformed event throws but leaves the instance fully usable", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    const cases = [
      [{ timestamp: 1 }, /action/, "missing required `action`"],
      [{ action: "Drupe::Action::Read", timestamp: "soon" }, /i64|timestamp/, "wrong-typed timestamp"],
      [null, /EventInput|invalid/, "null instead of an object"],
      [{ action: "Drupe::Action::Read", entities: "nope" }, /invalid|sequence/, "wrong-typed entities"],
    ];
    for (const [bad, pattern, label] of cases) {
      const e = throws(() => auth.isAuthorized(bad), `expected a throw for ${label}`);
      assert(e instanceof Error, `${label}: is a real Error`);
      assert(
        pattern.test(e.message),
        `${label}: message should match ${pattern}, got ${e.message}`,
      );
      // The instance must still work after EACH failure, not just the last.
      const ok = auth.isAuthorized(event(1));
      assert(ok !== undefined && ok.verdict === "allow", `${label}: instance still decides`);
      assert(typeof auth.decisionCount === "number", `${label}: getters still work`);
    }
    auth.reset(); // must also still work
  } finally {
    // The real tell: a poisoned instance cannot be freed at all.
    auth.free();
  }
});

check("optional event fields all default", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    // Only `action` is required; everything else has a default. A bare event
    // must not throw (it decides on an empty request, which denies).
    const d = auth.isAuthorized({ action: "Drupe::Action::Read" });
    assert(d !== undefined, "kind defaults to `request`, so this is a decision point");
    assert(d.timestamp === 0, "timestamp defaults to 0, got " + d.timestamp);
    assert(d.verdict === "deny", "an attribute-less request denies");
  } finally {
    auth.free();
  }
});

check("entities merge across attrs and parents for the same (type, id)", () => {
  const policy = `permit(principal in Drupe::Gateway::"fleet", action == Drupe::Action::"Read", resource)
when { principal.id == "alice" };`;
  const schema = `namespace Drupe {
  entity Gateway;
  entity OAuthUser in [Gateway] = { id: String } tags String;
  type ReadInput = { document: String };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ReadInput }
  };
}`;
  const auth = new dw.DogwoodAuthorizer(policy, schema);
  try {
    // One entity carrying BOTH an attribute and a parent: the policy needs both
    // to allow, so a builder that dropped either would deny.
    const d = auth.isAuthorized(
      event(1, {
        entities: [
          {
            type: "Drupe::OAuthUser",
            id: "alice",
            attrs: { id: "alice" },
            parents: [{ type: "Drupe::Gateway", id: "fleet" }],
          },
        ],
      }),
    );
    assert(d.verdict === "allow", "attrs and parents must compose: " + JSON.stringify(d));
  } finally {
    auth.free();
  }
});

check("a wrong-typed entity attribute fails closed WITH a cause", () => {
  const policy = `permit(principal, action == Drupe::Action::"Read", resource)
when { principal.id == "alice" };`;
  const auth = new dw.DogwoodAuthorizer(policy, SCHEMA);
  try {
    // `id` is declared String; supply an Int.
    const d = auth.isAuthorized(event(1, {
      entities: [{ type: "Drupe::OAuthUser", id: "alice", attrs: { id: 42 } }],
    }));
    assert(d.verdict === "deny", "must not allow on a schema violation");
    assert(
      d.errors.length > 0,
      "a fail-closed deny must carry its cause, else it looks like policy-said-no",
    );
  } finally {
    auth.free();
  }
});

// ═══ 9. lifecycle ════════════════════════════════════════════════════
console.log("\nlifecycle");

check("Symbol.dispose frees the instance (explicit resource management)", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  assert(typeof auth[Symbol.dispose] === "function", "the class implements Symbol.dispose");
  auth[Symbol.dispose]();
  throws(() => auth.isAuthorized(event(1)), "disposed instance must be unusable");
});

check("reset re-lowers and preserves the override arguments", () => {
  // If reset dropped the providers argument, the provider would become
  // unresolvable and the verdict would flip to a deny-with-errors.
  const auth = new dw.DogwoodAuthorizer(GUARDRAIL_POLICY, SCHEMA, undefined, PROVIDERS_INLINE);
  try {
    const before = auth.isAuthorized(event(0, {
      logged: { input: { document: "ABC" } }, context: { input: { document: "ABC" } },
    }));
    assert(before.verdict === "allow", "precondition");
    auth.reset();
    const after = auth.isAuthorized(event(1, {
      logged: { input: { document: "ABC" } }, context: { input: { document: "ABC" } },
    }));
    assert(
      after.verdict === "allow",
      "the providers override must survive reset, got " + JSON.stringify(after),
    );
    assert(after.index === 0, "index restarts");
  } finally {
    auth.free();
  }
});

check("many instances can coexist with independent histories", () => {
  const TEMPORAL = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 1h Drupe::Action::"Read"::response{} };`;
  const a = new dw.DogwoodAuthorizer(TEMPORAL, SCHEMA);
  const b = new dw.DogwoodAuthorizer(TEMPORAL, SCHEMA);
  try {
    // Record a response in `a` only; `b` must be unaffected.
    a.isAuthorized(event(1000, { kind: "response", logged: { input: { document: "d" }, output: { content: "c" } }, context: { input: { document: "d" }, output: { content: "c" } } }));
    assert(a.isAuthorized(event(1010)).verdict === "allow", "a has history");
    assert(b.isAuthorized(event(1010)).verdict === "deny", "b's history is separate");
  } finally {
    a.free();
    b.free();
  }
});

// The ordering contract is what the temporal operators rest on, so violating it
// does not fail — it quietly produces wrong answers. Enforced, and the boundary
// (equal is fine, earlier is not) pinned in both directions.
check("the non-decreasing-timestamp contract is enforced", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    assert(auth.lastTimestamp === undefined, "undefined before the first event");
    assert(auth.isAuthorized(event(500)).timestamp === 500, "echoed");
    assert(auth.lastTimestamp === 500, "lastTimestamp tracks it, got " + auth.lastTimestamp);
    // Equal is non-decreasing, so it is allowed: two events can share a second.
    assert(auth.isAuthorized(event(500)) !== undefined, "an equal timestamp is accepted");
    const e = throws(() => auth.isAuthorized(event(100)), "an earlier timestamp must be rejected");
    assert(e.name === "DogwoodError", "name, got " + e.name);
    assert(/100/.test(e.message) && /500/.test(e.message), "names both, got " + e.message);
    // Rejected, so not observed: the watermark has not moved.
    assert(auth.lastTimestamp === 500, "watermark unmoved, got " + auth.lastTimestamp);
    assert(auth.isAuthorized(event(600)) !== undefined, "and a later event still works");
    // A history-only event advances the watermark too — it enters the same history.
    auth.isAuthorized(event(700, { kind: "response", logged: { input: { document: "d" }, output: { content: "c" } }, context: { input: { document: "d" }, output: { content: "c" } } }));
    assert(auth.lastTimestamp === 700, "history-only events count, got " + auth.lastTimestamp);
    throws(() => auth.isAuthorized(event(650)), "and are ordered against too");
  } finally {
    auth.free();
  }
});

check("reset clears the timestamp watermark, so a fresh history may start earlier", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    auth.isAuthorized(event(9000));
    assert(auth.lastTimestamp === 9000, "watermark set");
    auth.reset();
    assert(auth.lastTimestamp === undefined, "cleared by reset, got " + auth.lastTimestamp);
    // Would throw against the old watermark; a reset history is a new ordering.
    assert(auth.isAuthorized(event(5)) !== undefined, "an earlier timestamp is fine post-reset");
  } finally {
    auth.free();
  }
});

// `lastTimestamp` must be a plain number, not a BigInt: an i64 returned raw
// crosses as BigInt, which is `!==` every number it would be compared against
// and throws on mixed arithmetic.
check("lastTimestamp is a number, comparable with a decision's timestamp", () => {
  const auth = new dw.DogwoodAuthorizer(ALLOW_ALL, SCHEMA);
  try {
    const d = auth.isAuthorized(event(1234));
    assert(typeof auth.lastTimestamp === "number", "got " + typeof auth.lastTimestamp);
    assert(auth.lastTimestamp === d.timestamp, "strictly equal to the decision's timestamp");
    assert(auth.lastTimestamp - 34 === 1200, "and usable in arithmetic");
  } finally {
    auth.free();
  }
});

// ═══ 10. limitations the bindings do NOT close ═══════════════════════
//
// The live authorizer validates events; `replay` does not, because it drives the
// frontend's own `.log` parser and the parsed events are not inspectable from
// outside the crate. So the same mistake is caught on one path and not the other.
// Asserted rather than merely written down, so that if upstream ever tightens the
// trace path these tests fail and the README stops being wrong.
console.log("\nknown limitations (recorded, not endorsed)");

check("LIMITATION: replay does not reject a bare action id — it denies silently", () => {
  const bare =
    `@1 scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") ` +
    `request_context(input: { document: "d" }) ` +
    `Action::"Read"::request(callerPrincipal: Drupe::OAuthUser::"alice", input: { document: "d" })`;
  const r = dw.replay(ALLOW_ALL, SCHEMA, bare);
  assert(r.verdicts.length === 1, "the trace still produces a verdict");
  assert(r.verdicts[0].verdict === "deny", "and it denies, got " + r.verdicts[0].verdict);
  assert(
    r.verdicts[0].errors.length === 0,
    "with NO stated cause — the live authorizer rejects this, replay does not",
  );
});

check("LIMITATION: replay accepts a backwards timestamp in a trace", () => {
  const line = (ts) =>
    `@${ts} scope(principal: Drupe::OAuthUser::"alice", resource: Drupe::Gateway::"gw1") ` +
    `request_context(input: { document: "d" }) ` +
    `Drupe::Action::"Read"::request(callerPrincipal: Drupe::OAuthUser::"alice", input: { document: "d" })`;
  const r = dw.replay(ALLOW_ALL, SCHEMA, `${line(100)}\n${line(50)}`);
  assert(r.verdicts.length === 2, "both events replay");
  assert(
    r.verdicts[0].timestamp === 100 && r.verdicts[1].timestamp === 50,
    "out of order, unremarked — the ordering contract is enforced only on the live path",
  );
});

check("LIMITATION: temporal history is never pruned, so a long-lived instance grows", () => {
  const TEMPORAL = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 1h Drupe::Action::"Read"::response{} };`;
  const auth = new dw.DogwoodAuthorizer(TEMPORAL, SCHEMA);
  const response = (ts) =>
    event(ts, {
      kind: "response",
      logged: { input: { document: "d" }, output: { content: "c" } },
      context: { input: { document: "d" }, output: { content: "c" } },
    });
  try {
    const before = process.memoryUsage().external;
    // 4000 events 100s apart span ~4.6 days — every one of them far outside the
    // default 24h `max_window`, so none can affect any future decision.
    for (let i = 1; i <= 4000; i++) auth.isAuthorized(response(i * 100));
    const grew = process.memoryUsage().external - before;
    assert(
      grew > 1e6,
      "recording the CURRENT behaviour: memory grows with event count regardless " +
        "of max_window (got " + (grew / 1e6).toFixed(1) + " MB). If this ever fails, " +
        "upstream has started pruning and the README's note should be removed.",
    );
    // The window still bounds the SEMANTICS, even though it does not bound memory:
    // a response 4.6 days old cannot satisfy `formerly within 1h`.
    const d = auth.isAuthorized(event(4000 * 100 + 86400));
    assert(d.verdict === "deny", "stale history does not leak into the verdict");
  } finally {
    auth.free();
  }
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
