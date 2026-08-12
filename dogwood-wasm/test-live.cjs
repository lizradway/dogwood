// Tests for the live, stateful authorizer (`DogwoodAuthorizer`).
//
// The load-bearing test here is **parity with `replay`**: the same events, fed
// one at a time through the live class, must produce exactly the verdict stream
// that the already-trusted whole-trace `replay` produces for the equivalent
// `.log` trace. That checks the part of this binding that can actually be wrong
// — the JS-object → `Event` mapping — without this suite having to re-assert
// Dogwood's own temporal semantics.
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

const ACTION_SCHEMA = `
namespace Drupe {
    entity Group;
    // The "in [Group]" clause is required for a policy scope of the form
    // "principal in Drupe::Group::..." to resolve: Cedar rejects an entity
    // whose parent type the schema does not declare ("entity does not conform
    // to the schema") rather than treating it as a non-member.
    entity User in [Group] { dept?: String };
    entity Gateway;
    type ReadInput = { document: String, user: String };
    type ReadOutput = { content: String };
    action "Read" appliesTo {
        principal: [User],
        resource: [Gateway],
        context: { input: ReadInput, output: ReadOutput }
    };
}`;

const POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.document like "*report*" };`;

// Permit a Read only if it matches the document rule AND a Read *response* was
// seen within the hour.
//
// Keying the temporal clause on the `response` kind (not `request`) is what
// makes this a real test of accumulated state: `Authorizer::is_authorized`
// observes the event into history *before* deciding, so a `request` event is
// its own predecessor and a `formerly … request{}` clause is already satisfied
// on the very first call. A `response` is history-only, so the verdict can only
// flip because an *earlier, separate* call recorded one.
const TEMPORAL_POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.document like "*report*" }
when temporal { formerly within 1h Drupe::Action::"Read"::response{} };`;

const PRINCIPAL = { type: "Drupe::User", id: "alice" };
const RESOURCE = { type: "Drupe::Gateway", id: "gw1" };

/** One live Read event. Timestamps are in SECONDS. */
function readEvent(ts, doc = "quarterly report") {
  const input = { document: doc, user: "alice" };
  return {
    action: "Drupe::Action::Read",
    kind: "request",
    timestamp: ts,
    principal: PRINCIPAL,
    resource: RESOURCE,
    // `input` is needed by both halves, so it is supplied to both: `logged`
    // for temporal correlation, `context` for the Cedar request.
    logged: { input },
    context: { input },
  };
}

/** The history-only `response` half of a Read, which records `output`. */
function responseEvent(ts, doc = "quarterly report") {
  const input = { document: doc, user: "alice" };
  const output = { content: "..." };
  return {
    action: "Drupe::Action::Read",
    kind: "response",
    timestamp: ts,
    principal: PRINCIPAL,
    resource: RESOURCE,
    logged: { input, output },
    context: { input, output },
  };
}

/** Render a Dogwood value in the `.log` surface syntax. */
function logValue(v) {
  if (v === null) return "null";
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[ ${v.map(logValue).join(", ")} ]`;
  if (v.__entity) return `${v.__entity.type}::${JSON.stringify(v.__entity.id)}`;
  if (v.__decimal) return v.__decimal;
  const body = Object.entries(v)
    .map(([k, val]) => `${k}: ${logValue(val)}`)
    .join(", ");
  return `{ ${body} }`;
}

/**
 * Render an `EventInput` as the equivalent `.log` line, so the parity test
 * drives both paths from one description instead of two hand-written ones.
 *
 * `callerPrincipal`/`callerResource` are written into the logged record
 * explicitly: the builder path gets them for free (`principal_for` /
 * `resource_for` insert them), but the `.log` parser treats `scope(...)` and the
 * trailing logged record as independent, so a truly equivalent trace must state
 * them. This matters under the pinned default schema, where temporal predicates
 * correlate on `callerPrincipal`.
 */
function toLogLine(event) {
  const parts = [`@${event.timestamp}`];

  if (event.principal || event.resource) {
    const scope = [];
    if (event.principal) scope.push(`principal: ${logValue({ __entity: event.principal })}`);
    if (event.resource) scope.push(`resource: ${logValue({ __entity: event.resource })}`);
    parts.push(`scope(${scope.join(", ")})`);
  }

  const context = Object.entries(event.context ?? {});
  if (context.length > 0) {
    parts.push(
      `request_context(${context.map(([g, f]) => `${g}: ${logValue(f)}`).join(", ")})`,
    );
  }

  const logged = Object.entries(event.logged ?? {}).map(
    ([g, f]) => `${g}: ${logValue(f)}`,
  );
  if (event.principal) {
    logged.unshift(`callerPrincipal: ${logValue({ __entity: event.principal })}`);
  }
  if (event.resource) {
    logged.push(`callerResource: ${logValue({ __entity: event.resource })}`);
  }

  const [ns, id] = [
    event.action.slice(0, event.action.lastIndexOf("::")),
    event.action.slice(event.action.lastIndexOf("::") + 2),
  ];
  parts.push(`${ns}::${JSON.stringify(id)}::${event.kind}(${logged.join(", ")})`);

  return parts.join(" ");
}

console.log("Dogwood live-authorizer tests\n");

check("live authorizer allows a matching read", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  const d = auth.isAuthorized(readEvent(1000));
  assert(d !== undefined, "a request-kind event yields a decision");
  assert(d.verdict === "allow", "expected allow, got " + d.verdict + " " + JSON.stringify(d.errors));
  assert(d.allowed === true, "allowed mirrors verdict");
  assert(d.index === 0, "first decision is index 0");
  assert(d.timestamp === 1000, "timestamp echoed");
  assert(Array.isArray(d.determining_rules), "determining_rules present");
});

check("live authorizer denies a non-matching read", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  const d = auth.isAuthorized(readEvent(1000, "grocery list"));
  assert(d.verdict === "deny", "expected deny, got " + d.verdict);
  assert(d.allowed === false, "allowed mirrors verdict");
  assert(d.errors.length === 0, "a policy-said-no deny carries no errors: " + JSON.stringify(d.errors));
});

check("a history-only event returns undefined and yields no decision", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  const response = auth.isAuthorized({
    ...readEvent(1000),
    kind: "response",
  });
  assert(response === undefined, "response-kind is history-only, got " + JSON.stringify(response));
  assert(auth.decisionCount === 0, "history-only does not advance the decision index");
});

check("decision index advances only on decision points", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  assert(auth.decisionCount === 0, "starts at 0");
  auth.isAuthorized(readEvent(1000));
  auth.isAuthorized({ ...readEvent(1010), kind: "response" });
  const third = auth.isAuthorized(readEvent(1020));
  assert(auth.decisionCount === 2, "two decisions, got " + auth.decisionCount);
  assert(third.index === 1, "second decision is index 1, got " + third.index);
});

// ── the parity test ──────────────────────────────────────────────────
//
// Same scenario, two ways. If the event mapping is wrong in any way that
// matters (scope, logged record, request context, timestamps), the temporal
// policy's verdicts diverge here.
check("live verdict stream matches replay over the equivalent trace", () => {
  // A scenario chosen so the verdict stream actually VARIES — a parity test
  // where everything allows would pass even if the temporal path were dead.
  //
  //   @1000 request "quarterly report" -> deny  (no response in history yet)
  //   @1010 response                   -> no decision (history-only)
  //   @1020 request "quarterly report" -> allow (response within the hour)
  //   @1030 request "grocery list"     -> deny  (fails the document rule)
  //   @9000 request "quarterly report" -> deny  (response is 7990s back, > 1h)
  const events = [
    readEvent(1000),
    responseEvent(1010),
    readEvent(1020),
    readEvent(1030, "grocery list"),
    readEvent(9000),
  ];
  const decisionPoints = events.filter((e) => e.kind === "request").length;

  const trace = events.map(toLogLine).join("\n");
  const expected = dw.replay(TEMPORAL_POLICY, ACTION_SCHEMA, trace).verdicts;

  const auth = new dw.DogwoodAuthorizer(TEMPORAL_POLICY, ACTION_SCHEMA);
  const actual = events.map((e) => auth.isAuthorized(e)).filter((d) => d !== undefined);

  assert(
    expected.length === decisionPoints,
    `replay produced ${expected.length} verdicts for ${decisionPoints} decision points`,
  );
  assert(
    actual.length === expected.length,
    `live produced ${actual.length} decisions, replay ${expected.length}`,
  );
  // Guard against the scenario silently degenerating into all-allow/all-deny.
  assert(
    new Set(expected.map((v) => v.verdict)).size === 2,
    "scenario must produce both allow and deny to be a meaningful parity check, got: " +
      expected.map((v) => v.verdict).join(","),
  );

  for (let i = 0; i < expected.length; i++) {
    assert(
      actual[i] !== undefined,
      `live event ${i} produced no decision but replay produced one`,
    );
    assert(
      actual[i].verdict === expected[i].verdict,
      `verdict ${i}: live=${actual[i].verdict} replay=${expected[i].verdict}`,
    );
    assert(
      actual[i].timestamp === expected[i].timestamp,
      `timestamp ${i}: live=${actual[i].timestamp} replay=${expected[i].timestamp}`,
    );
    assert(
      JSON.stringify(actual[i].determining_rules) ===
        JSON.stringify(expected[i].determining_rules),
      `determining_rules ${i}: live=${JSON.stringify(actual[i].determining_rules)} ` +
        `replay=${JSON.stringify(expected[i].determining_rules)}`,
    );
  }
  console.log(
    "        verdicts: " + expected.map((v) => `@${v.timestamp}:${v.verdict}`).join(" "),
  );
});

check("temporal state accumulates across separate calls", () => {
  // The point of the live class: a history-only event fed in one call must
  // change the verdict of a request fed in a LATER call.
  const auth = new dw.DogwoodAuthorizer(TEMPORAL_POLICY, ACTION_SCHEMA);

  const before = auth.isAuthorized(readEvent(1000));
  assert(before.verdict === "deny", "no response in history yet -> deny, got " + before.verdict);

  const recorded = auth.isAuthorized(responseEvent(1010));
  assert(recorded === undefined, "the response is history-only");

  const after = auth.isAuthorized(readEvent(1020));
  assert(
    after.verdict === "allow",
    "a response recorded by an earlier call must flip the verdict, got " +
      after.verdict + " " + JSON.stringify(after.errors),
  );
});

check("the temporal window is honoured across calls", () => {
  // Same as above but past the 1h window: history exists, yet is too old.
  const auth = new dw.DogwoodAuthorizer(TEMPORAL_POLICY, ACTION_SCHEMA);
  auth.isAuthorized(responseEvent(1000));
  const inWindow = auth.isAuthorized(readEvent(1000 + 3599));
  const outOfWindow = auth.isAuthorized(readEvent(1000 + 3601));
  assert(inWindow.verdict === "allow", "3599s < 1h -> allow, got " + inWindow.verdict);
  assert(outOfWindow.verdict === "deny", "3601s > 1h -> deny, got " + outOfWindow.verdict);
});

check("reset clears temporal history", () => {
  const auth = new dw.DogwoodAuthorizer(TEMPORAL_POLICY, ACTION_SCHEMA);
  auth.isAuthorized(responseEvent(1000));
  const withHistory = auth.isAuthorized(readEvent(1010));
  assert(withHistory.verdict === "allow", "precondition: history allows the read");

  auth.reset();
  assert(auth.decisionCount === 0, "reset restarts the decision index");

  const afterReset = auth.isAuthorized(readEvent(1020));
  assert(
    afterReset.verdict === "deny",
    "after reset the recorded response is gone, so the read denies again; got " +
      afterReset.verdict,
  );
  assert(afterReset.index === 0, "index restarts at 0");
});

check("entity attributes are readable by a policy", () => {
  const policy = `permit(principal, action == Drupe::Action::"Read", resource)
when { principal.dept == "eng" };`;
  const auth = new dw.DogwoodAuthorizer(policy, ACTION_SCHEMA);

  const allowed = auth.isAuthorized({
    ...readEvent(1000),
    entities: [{ type: "Drupe::User", id: "alice", attrs: { dept: "eng" } }],
  });
  assert(allowed.verdict === "allow", "eng dept allowed, got " + JSON.stringify(allowed));

  const denied = auth.isAuthorized({
    ...readEvent(1010),
    entities: [{ type: "Drupe::User", id: "alice", attrs: { dept: "sales" } }],
  });
  assert(denied.verdict === "deny", "sales dept denied, got " + denied.verdict);
});

check("entity parents resolve membership (principal in Group)", () => {
  const policy = `permit(principal in Drupe::Group::"admins", action == Drupe::Action::"Read", resource);`;
  const auth = new dw.DogwoodAuthorizer(policy, ACTION_SCHEMA);

  const inGroup = auth.isAuthorized({
    ...readEvent(1000),
    entities: [
      {
        type: "Drupe::User",
        id: "alice",
        parents: [{ type: "Drupe::Group", id: "admins" }],
      },
    ],
  });
  assert(inGroup.verdict === "allow", "member allowed, got " + JSON.stringify(inGroup));

  const notInGroup = auth.isAuthorized({
    ...readEvent(1010),
    entities: [
      {
        type: "Drupe::User",
        id: "alice",
        parents: [{ type: "Drupe::Group", id: "interns" }],
      },
    ],
  });
  assert(notInGroup.verdict === "deny", "non-member denied, got " + notInGroup.verdict);
});

check("an id needing escaping round-trips (no hand-escaping, no double-escaping)", () => {
  // `principal_for`/`entity_for` take the DECODED id and escape it once, so a
  // quote in the id must not break the lookup that reads the attribute.
  const policy = `permit(principal, action == Drupe::Action::"Read", resource)
when { principal.dept == "eng" };`;
  const auth = new dw.DogwoodAuthorizer(policy, ACTION_SCHEMA);
  const weirdId = 'ali"ce';
  const d = auth.isAuthorized({
    ...readEvent(1000),
    principal: { type: "Drupe::User", id: weirdId },
    entities: [{ type: "Drupe::User", id: weirdId, attrs: { dept: "eng" } }],
  });
  assert(
    d.verdict === "allow",
    "attribute lookup must match the escaped uid, got " + JSON.stringify(d),
  );
});

check("__entity and __decimal tagged values are accepted", () => {
  // Exercised through a passing policy: the point is that conversion does not
  // throw and the request builds.
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  const d = auth.isAuthorized({
    ...readEvent(1000),
    logged: {
      input: { document: "quarterly report", user: "alice" },
      extra: {
        who: { __entity: { type: "Drupe::User", id: "bob" } },
        amount: { __decimal: "1.50" },
        ratio: 2.5,
        tags: ["a", "b"],
        nested: { deep: true, none: null },
      },
    },
  });
  assert(d.verdict === "allow", "tagged values do not disturb the decision");
});

check("a malformed __entity tag throws", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  let threw = null;
  try {
    auth.isAuthorized({
      ...readEvent(1000),
      logged: { extra: { who: { __entity: { type: "Drupe::User" } } } }, // no id
    });
  } catch (e) {
    threw = e;
  }
  assert(threw !== null, "expected a throw for a malformed __entity");
  assert(threw instanceof Error, "throws a real Error");
  assert(
    /__entity/.test(threw.message),
    "message names the offending tag, got: " + threw.message,
  );
});

check("a bad policy throws DogwoodError from the constructor", () => {
  let threw = null;
  try {
    new dw.DogwoodAuthorizer("permit(principal action resource);", ACTION_SCHEMA);
  } catch (e) {
    threw = e;
  }
  assert(threw !== null, "expected a throw");
  assert(threw.name === "DogwoodError", "name is DogwoodError, got " + threw.name);
  assert(
    threw.diagnostic && typeof threw.diagnostic.message === "string",
    "carries a structured .diagnostic",
  );
});

check("free() releases the instance and is safe to call once", () => {
  // The class owns wasm-side memory (lowered policy set + temporal history)
  // that JS GC does not reclaim, so a long-lived host must free it. Creating
  // and freeing many instances must not fault.
  for (let i = 0; i < 25; i++) {
    const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
    assert(auth.isAuthorized(readEvent(1000 + i)).verdict === "allow", "decides before free");
    auth.free();
  }
});

check("using a freed instance throws rather than corrupting memory", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  auth.free();
  let threw = null;
  try {
    auth.isAuthorized(readEvent(1000));
  } catch (e) {
    threw = e;
  }
  assert(threw !== null, "expected use-after-free to throw");
});

check("kind defaults to request when omitted", () => {
  const auth = new dw.DogwoodAuthorizer(POLICY, ACTION_SCHEMA);
  const event = readEvent(1000);
  delete event.kind;
  const d = auth.isAuthorized(event);
  assert(d !== undefined, "omitted kind defaults to the decision kind `request`");
  assert(d.verdict === "allow", "and decides normally");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
