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
    replaceChildren(...nodes) { this.children = nodes; },
    showModal() { this.open = true; this.opens++; }, close() { this.open = false; }
  };
}
const html = fs.readFileSync("web/index.html", "utf8");
const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
const document = {
  getElementById(id) { assert(nodes.has(id), `Missing HTML element: ${id}`); return nodes.get(id); },
  documentElement: element(), querySelectorAll: () => [], querySelector: () => element(),
  createElement: element, createTextNode: text => ({textContent: text})
};
const source = fs.readFileSync("web/app.js", "utf8").replace(
  /  poll\(\);\s+setInterval\(poll, 1300\);\s+setInterval\(renderElapsed, 1000\);/,
  "globalThis.ui = {renderSummary, renderElapsed, setSelected(value) { selected = value; }};"
);
assert(source.includes("globalThis.ui"), "Could not isolate UI rendering from network startup");
const storage = {getItem: () => null, setItem() {}};
const context = {document, localStorage: storage, sessionStorage: storage,
  location: {hash: ""}, URLSearchParams, matchMedia: () => ({matches: false})};
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
