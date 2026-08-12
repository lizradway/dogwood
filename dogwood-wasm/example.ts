// Type-checking sample: exercises the generated TypeScript definitions.
// Compiled with `tsc --strict --noEmit` — no JS is emitted; this only proves
// the .d.ts is sound and the report shapes are correctly typed.
import {
  validate,
  lower,
  replay,
  checkParse,
  mcpToCedarSchema,
  DogwoodAuthorizer,
  type ValidateReport,
  type LowerArtifacts,
  type ReplayReport,
  type Diagnostic,
  type Verdict,
  type DogwoodError,
  type EventInput,
  type AuthorizerDecision,
} from "./pkg/dogwood_wasm.js";

const ACTION_SCHEMA = `namespace Drupe {
  entity User; entity Gateway;
  type ReadInput = { document: String, user: String };
  type ReadOutput = { content: String };
  action "Read" appliesTo {
    principal: [User], resource: [Gateway],
    context: { input: ReadInput, output: ReadOutput }
  };
}`;

const POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.document like "*report*" };`;

// validate() -> ValidateReport, fully typed.
const report: ValidateReport = validate(POLICY, ACTION_SCHEMA);
if (!report.passed) {
  report.errors.forEach((d: Diagnostic) => {
    // `severity` is the union "error" | "warning" | "advice".
    console.error(`[${d.severity}] ${d.message}`);
    d.labels.forEach((l) => console.error(`  at bytes ${l.start}..${l.start + l.len}`));
  });
}

// lower() -> LowerArtifacts.
const art: LowerArtifacts = lower(POLICY, ACTION_SCHEMA);
const _cedar: string = art.cedar_policies;
const _selfContained: boolean = art.self_contained;

// replay() -> ReplayReport with a discriminated Verdict union.
const trace =
  `@1000 scope(principal: Drupe::User::"alice", resource: Drupe::Gateway::"gw1") ` +
  `request_context(input: { document: "report", user: "alice" }) ` +
  `Drupe::Action::"Read"::request()`;
const rr: ReplayReport = replay(POLICY, ACTION_SCHEMA, trace);
rr.verdicts.forEach((v) => {
  const verdict: Verdict = v.verdict; // "allow" | "deny"
  console.log(`@${v.timestamp} #${v.index}: ${verdict}`);
});

// Optional overrides are typed as `string | null | undefined`.
const parsed = checkParse(POLICY, undefined, undefined, undefined);
const _n: number = parsed.policy_count;

const _schema: string = mcpToCedarSchema("[]");

// Errors are thrown; the structured payload is typed via DogwoodError.
try {
  validate("permit(", ACTION_SCHEMA);
} catch (e) {
  const err = e as DogwoodError;
  console.error(err.diagnostic.message, err.diagnostic.severity);
}

// ── the live, stateful authorizer ────────────────────────────────────
//
// Lower once, then decide per event as it happens. Temporal history
// accumulates across calls, so this instance is one history.
const auth = new DogwoodAuthorizer(POLICY, ACTION_SCHEMA);

// Timestamps are in SECONDS (a `within 1h` window is 3600), so a live host
// divides `Date.now()` down rather than passing it straight through.
const now = Math.floor(Date.now() / 1000);

const request: EventInput = {
  action: "Drupe::Action::Read", // qualified, id UNquoted
  kind: "request",
  timestamp: now,
  principal: { type: "Drupe::User", id: "alice" },
  resource: { type: "Drupe::Gateway", id: "gw1" },
  // `input` is read by both halves, so it is supplied to both: `logged` is the
  // durable temporal record, `context` the ephemeral Cedar request context.
  logged: { input: { document: "quarterly report", user: "alice" } },
  context: { input: { document: "quarterly report", user: "alice" } },
  entities: [{ type: "Drupe::User", id: "alice", attrs: { dept: "eng" } }],
};

// A decision-kind event yields a decision; a history-only one yields undefined.
const decision: AuthorizerDecision | undefined = auth.isAuthorized(request);
if (decision !== undefined) {
  const v: Verdict = decision.verdict;
  console.log(`#${decision.index} ${v} (rules ${decision.determining_rules.join(",")})`);
  // A deny carrying errors is a fail-closed evaluation failure, not "policy said no".
  if (!decision.allowed && decision.errors.length > 0) {
    console.error("evaluation failed:", decision.errors.join("; "));
  }
}

// Record the response half so later temporal predicates can correlate on it.
// History-only: returns undefined.
const noDecision: AuthorizerDecision | undefined = auth.isAuthorized({
  ...request,
  kind: "response",
});
if (noDecision === undefined) console.log("history-only event: no verdict");

const _count: number = auth.decisionCount;

// `isAuthorized` returns undefined both for a legitimately history-only kind and
// for a kind the event schema never declared, so a typo yields no decision
// rather than an error. When the kind comes from anywhere untrusted, check it.
const kinds: string[] = auth.decisionKinds;
function isDecisionPoint(kind: string): boolean {
  return kinds.includes(kind);
}
console.log(isDecisionPoint("request"), isDecisionPoint("requst"));

auth.reset(); // drop accumulated history, re-lower the same sources

// An authorizer owns wasm-side memory (the lowered policy set plus the temporal
// history) that JS garbage collection does NOT reclaim. Free it when done, or
// bind it with `using` so it is disposed at end of scope.
auth.free();

function decideOnce(policySrc: string, schemaSrc: string, event: EventInput): Verdict {
  using scoped = new DogwoodAuthorizer(policySrc, schemaSrc);
  return scoped.isAuthorized(event)?.verdict ?? "deny";
}
console.log(decideOnce(POLICY, ACTION_SCHEMA, request));
