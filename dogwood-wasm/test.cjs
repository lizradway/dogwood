// End-to-end smoke test of the Dogwood WASM bindings (Node target).
const dw = require("./pkg/dogwood_wasm.js");

let pass = 0, fail = 0;
function check(name, fn) {
  try { fn(); console.log(`  ok   ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}: ${e && e.message ? e.message : e}`); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || "assertion failed"); }

// A small Cedar action schema (the multi-action starter, trimmed to Read).
const ACTION_SCHEMA = `
namespace Drupe {
    entity User;
    entity Gateway;
    type ReadInput = { document: String, user: String };
    type ReadOutput = { content: String };
    action "Read" appliesTo {
        principal: [User],
        resource: [Gateway],
        context: { input: ReadInput, output: ReadOutput }
    };
}`;

// A plain (non-temporal) policy: allow reads of documents whose name matches.
const POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when { context.input.document like "*report*" };`;

// A temporal policy: permit a Read only if a Read formerly happened within 1h.
const TEMPORAL_POLICY = `permit(principal, action == Drupe::Action::"Read", resource)
when temporal { formerly within 1h Drupe::Action::"Read"::request{} };`;

console.log("Dogwood WASM binding tests\n");

check("checkActionSchema accepts a valid schema", () => {
  const r = dw.checkActionSchema(ACTION_SCHEMA);
  assert(r.ok === true, "expected ok");
  assert(r.kind === "action", "kind");
});

check("checkParse summarizes a parsed policy", () => {
  const r = dw.checkParse(POLICY);
  assert(r.policy_count === 1, "policy_count");
  assert(r.policies[0].uses_temporal === false, "uses_temporal");
});

check("checkParse detects temporal use", () => {
  const r = dw.checkParse(TEMPORAL_POLICY);
  assert(r.policies[0].uses_temporal === true, "uses_temporal");
  assert(r.policies[0].temporal_count === 1, "temporal_count");
});

check("validate passes for a well-typed policy", () => {
  const r = dw.validate(POLICY, ACTION_SCHEMA);
  assert(r.passed === true, "expected passed, got errors: " + JSON.stringify(r.errors));
});

check("lower emits Cedar artifacts", () => {
  const r = dw.lower(POLICY, ACTION_SCHEMA);
  assert(typeof r.cedar_policies === "string" && r.cedar_policies.length > 0, "cedar_policies");
  assert(r.self_contained === true, "a non-temporal policy lowers to self-contained Cedar");
});

check("lower marks a temporal policy as NOT self-contained", () => {
  const r = dw.lower(TEMPORAL_POLICY, ACTION_SCHEMA);
  assert(r.self_contained === false, "temporal policy needs Dogwood at authorize time");
  assert(r.temporal_fields.length === 1, "one hoisted temporal field");
});

check("mcpToCedarSchema generates a schema from an MCP manifest", () => {
  const manifest = JSON.stringify([{
    name: "SellShares",
    description: "Sell shares of a stock.",
    inputSchema: { type: "object",
      properties: { stock: { type: "string" }, shares: { type: "integer" } },
      required: ["stock", "shares"] },
  }]);
  const schema = dw.mcpToCedarSchema(manifest);
  assert(schema.includes("SellShares"), "schema names the action");
});

check("error path throws a typed DogwoodError with .diagnostic", () => {
  try {
    dw.checkParse("permit(principal action resource);"); // missing commas -> parse error
    throw new Error("expected a throw");
  } catch (e) {
    assert(e instanceof Error, "is a real Error");
    assert(e.name === "DogwoodError", "name is DogwoodError, got " + e.name);
    assert(e.diagnostic && typeof e.diagnostic.message === "string", "has .diagnostic.message");
    assert(e.diagnostic.severity === "error", "severity");
    console.log("        diagnostic.message: " + e.diagnostic.message.split("\n")[0]);
  }
});

// replay: exercised with an empty/simple trace; format is validated below.
check("replay returns a verdict stream for a request trace", () => {
  const trace =
    `@1000 scope(principal: Drupe::User::"alice", resource: Drupe::Gateway::"gw1") ` +
    `request_context(input: { document: "quarterly report", user: "alice" }) ` +
    `Drupe::Action::"Read"::request()`;
  const r = dw.replay(POLICY, ACTION_SCHEMA, trace);
  assert(Array.isArray(r.verdicts), "verdicts is array");
  assert(r.verdicts.length === 1, "one decision point, got " + r.verdicts.length);
  console.log("        verdict[0]: " + JSON.stringify(r.verdicts[0]));
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
