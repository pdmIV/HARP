// Run with node tests/test_web_ui.js. No browser, server, or lab access required.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function element() {
  return {
    value: "", textContent: "", dataset: {}, children: [], handlers: {}, open: false, opens: 0,
    classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, fn) { this.handlers[name] = fn; },
    setAttribute() {}, append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.replacements = (this.replacements || 0) + 1; this.children = nodes; },
    showModal() { this.open = true; this.opens++; }, close() { this.open = false; }
  };
}
const html = fs.readFileSync("web/index.html", "utf8");
const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
const liveIndicator = element();
const document = {
  getElementById(id) { assert(nodes.has(id), `Missing HTML element: ${id}`); return nodes.get(id); },
  documentElement: element(), querySelectorAll: () => [], querySelector: selector => selector === ".live-indicator" ? liveIndicator : element(),
  createElement: element, createTextNode: text => ({textContent: text})
};
const source = fs.readFileSync("web/app.js", "utf8").replace(
  /  poll\(\);\s+setInterval\(poll, 1300\);\s+setInterval\(renderElapsed, 1000\);/,
  "globalThis.ui = {configPayload, renderSelections, renderSummary, renderElapsed, renderReplay, seekReplay, tickReplay, post, setReplay(value) { replay = value; }, setSelected(value) { selected = value; }};"
);
assert(source.includes("globalThis.ui"), "Could not isolate UI rendering from network startup");
const storage = {getItem: () => null, setItem() {}};
const context = {document, localStorage: storage, sessionStorage: storage,
  setInterval() {}, performance: {now: () => 1000}, location: {hash: ""}, URLSearchParams, matchMedia: () => ({matches: false})};
vm.createContext(context);
vm.runInContext(source, context);
nodes.get("artifactFilter").value = "all";
const state = {
  id: "test", summary: {status: "active", success: "unknown", mode: "hybrid"},
  started_epoch: Date.now() / 1000 - 120, duration_seconds: 75,
  activity: {}, flags: {}, artifacts: [], recon: []
};
context.ui.setSelected(state);
context.ui.renderSummary();
assert.equal(nodes.get("successDialog").opens, 0);
state.artifacts.push({id: "user", kind: "flag", title: "user.txt", value: "a".repeat(32)});
state.flags["user.txt"] = {found: true, artifact_id: "user"};
context.ui.renderSummary();
assert.equal(nodes.get("userFlagValue").textContent, "a".repeat(32));
assert.equal(nodes.get("artifactGrid").children.length, 1, "Artifacts must render without a new cycle");
state.artifacts.push({id: "root", kind: "flag", title: "root.txt", value: "b".repeat(32)});
state.flags["root.txt"] = {found: true, artifact_id: "root"};
state.summary.status = "finished";
state.summary.success = "yes";
context.ui.renderSummary();
assert.equal(nodes.get("sessionState").textContent, "FINISHED");
assert.equal(nodes.get("metricElapsed").textContent, "00:01:15");
assert.equal(nodes.get("successDialog").opens, 1);
assert.equal(nodes.get("artifactGrid").children.length, 2);
context.ui.renderElapsed();
context.ui.renderSummary();
assert.equal(nodes.get("metricElapsed").textContent, "00:01:15", "Completed timer must remain frozen");
assert.equal(nodes.get("successDialog").opens, 1, "Polling must not reopen the celebration");
nodes.get("closeSuccess").handlers.click();
assert.equal(nodes.get("successDialog").open, false);
assert.match(html, /rel="icon"[^>]+href="\/favicon.svg"/);
console.log("UI checks passed: live artifacts, flags, frozen timer, celebration, favicon link.");

// A rewind must clear future flags/artifacts, and replay must never send a POST.
const initial = {seconds: 0, event: null, summary: {status: "recon", success: "unknown"}, activity: {}, flags: {}, artifacts: [], recon: []};
const final = {seconds: 75, event: null, summary: {...state.summary}, activity: {}, flags: {...state.flags}, artifacts: [...state.artifacts], recon: []};
const playback = {id: "test", loading: false, playing: false, seconds: 0, index: -1, duration_seconds: 75,
  session: {id: "test", started_epoch: state.started_epoch}, frames: [initial, final], lastTick: 1000};
context.ui.setReplay(playback);
context.ui.seekReplay(75);
assert.equal(nodes.get("metricFlags").textContent, "2 / 2");
assert.equal(nodes.get("sessionState").textContent, "RECORDED REPLAY");
assert.equal(nodes.get("runManual").disabled, true);
assert.equal(nodes.get("startSession").disabled, true);
assert.throws(() => context.ui.post("/api/sessions/test/terminal", {}), /Exit recorded replay/);
context.ui.seekReplay(0);
assert.equal(nodes.get("metricFlags").textContent, "0 / 2");
assert.equal(nodes.get("metricElapsed").textContent, "00:00:00");
assert.equal(nodes.get("userFlagValue").textContent, "Awaiting capture");
assert.equal(nodes.get("successDialog").open, false);
playback.playing = true;
playback.lastTick = 0;
nodes.get("replaySpeed").value = "4";
context.ui.tickReplay();
assert.equal(playback.seconds, 4);
playback.playing = false;
context.ui.tickReplay();
assert.equal(playback.seconds, 4, "Paused replay must not advance");
console.log("Replay UI checks passed: seek, rewind, speed, pause, and blocked writes.");

context.ui.setReplay(null);
state.summary.local_model_calls = 1;
state.summary.local_estimated_usd = .045148;
state.summary.local_cost_basis = "current_configured_prices";
context.ui.setSelected(state);
context.ui.renderSummary();
assert.match(nodes.get("proxyApiCost").textContent, /\$0\.045148 estimated at current configured prices/);
console.log("Cost UI check passed: current-price estimate and source label.");

Object.assign(state.summary, {total_estimated_usd: .00228, oracle_only_estimated_usd: .0076,
  hybrid_savings_usd: .00532, hybrid_savings_percent: 70, cost_comparison_status: "same_workload_estimate"});
context.ui.renderSummary();
assert.equal(nodes.get("totalApiCost").textContent, "$0.002280");
assert.equal(nodes.get("oracleOnlyCost").textContent, "$0.007600");
assert.equal(nodes.get("hybridSavingsPercent").textContent, "70.0% estimated savings");
state.summary.hybrid_savings_usd = -.001;
state.summary.hybrid_savings_percent = -12.5;
context.ui.renderSummary();
assert.match(nodes.get("hybridSavings").textContent, /extra cost/);
assert.equal(nodes.get("hybridSavingsPercent").textContent, "12.5% higher cost");
console.log("Comparison UI checks passed: total, oracle-only estimate, dollar and percent savings.");

// Repeated polling must retain the same indicator dot and avoid DOM replacement.
const replacements = liveIndicator.replacements || 0;
context.ui.setReplay(null);
context.ui.setSelected(state);
context.ui.renderSummary();
context.ui.renderSummary();
assert.equal(nodes.get("activityStatusText").textContent, "SAVED SESSION");
assert.equal(liveIndicator.replacements || 0, replacements);
state.summary.status = "active";
context.ui.renderSummary();
assert.equal(nodes.get("activityStatusText").textContent, "LIVE");
assert.equal(liveIndicator.replacements || 0, replacements);
assert.match(fs.readFileSync("web/app.css", "utf8"), /\.live-indicator i\{animation:none/);
console.log("Status indicator checks passed: stable dot and static styling across refreshes.");

// Adaptive reasoning is opt-in and provider-scoped when saved.
nodes.get("oracleProvider").value = "zai";
nodes.get("oracleAdaptive").checked = true;
context.ui.renderSelections();
assert.equal(nodes.get("oracleReasoning").disabled, true);
assert.equal(context.ui.configPayload().oracle.adaptive_reasoning, true);
nodes.get("oracleAdaptive").checked = false;
context.ui.renderSelections();
assert.equal(nodes.get("oracleReasoning").disabled, false);
assert.equal(context.ui.configPayload().oracle.adaptive_reasoning, false);
nodes.get("oracleProvider").value = "codex";
nodes.get("oracleAdaptive").checked = true;
assert.equal(context.ui.configPayload().oracle.adaptive_reasoning, false);
console.log("Adaptive effort UI checks passed: toggle, fixed controls, and provider-scoped persistence.");
