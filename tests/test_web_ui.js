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
    insertBefore(node, before) {
      const old = this.children.indexOf(node); if (old >= 0) this.children.splice(old, 1);
      const index = before ? this.children.indexOf(before) : this.children.length;
      this.children.splice(index, 0, node);
    },
    removeChild(node) { this.children.splice(this.children.indexOf(node), 1); },
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
  "globalThis.ui = {renderArtifacts, SessionViewCache, sessionCache, prefetchRecentSessions, renderSessions, switchSession, cacheCompletedSession, poll, renderDependencies, configPayload, renderSelections, renderSummary, renderElapsed, renderReplay, seekReplay, tickReplay, post, setSessions(value) { sessions = value; }, setReplay(value) { replay = value; }, setSelected(value) { selected = value; }};"
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
nodes.get("runtimeSelect").value = "native";
nodes.get("runtimeSelect").handlers.change();
assert.equal(nodes.get("networkPolicy").value, "vpn_bridge");
assert.equal(nodes.get("networkPolicy").disabled, true);
nodes.get("runtimeSelect").value = "docker";
nodes.get("runtimeSelect").handlers.change();
assert.equal(nodes.get("networkPolicy").disabled, false);
assert.match(html, /option value="native">Native Kali Linux/);
console.log("Runtime UI checks passed: native selection, direct network policy, Docker policy editing.");

(async () => {
  const imageNodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
  imageNodes.get("artifactFilter").value = "image";
  const revoked = [], fetched = [];
  let resolveFetch;
  const imageContext = {...context, document: {...document, documentElement: element(), getElementById: id => imageNodes.get(id)},
    localStorage: {getItem: () => "image-session", setItem() {}},
    sessionStorage: {getItem: () => "test-token", setItem() {}},
    URL: {createObjectURL: () => "blob:image-clue", revokeObjectURL: url => revoked.push(url)},
    fetch: (url, options) => { fetched.push({url, options}); return new Promise(resolve => { resolveFetch = resolve; }); }};
  delete imageContext.ui;
  vm.createContext(imageContext); vm.runInContext(source, imageContext);
  const imageState = {id: "image-session", artifacts: [{id: "a".repeat(32), kind: "image", title: "Lab clue",
    value: "SHA-256: test", source: "/workspace/clue.png", evidence_backed: true,
    attachment: {filename: "clue.png", media_type: "image/png"}}]};
  imageContext.ui.setSelected(imageState);
  imageContext.ui.renderArtifacts(true);
  assert.equal(fetched[0].options.headers["X-HARP-Token"], "test-token");
  assert(fetched[0].url.endsWith("?preview=1"));
  const card = imageNodes.get("artifactGrid").children[0];
  const preview = card.children.find(child => child.className === "artifact-image-wrap");
  resolveFetch({ok: true, blob: async () => ({type: "image/png"})});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(preview.children[0].src, "blob:image-clue");
  assert.equal(preview.children[0].alt, "Lab clue");
  assert.equal(preview.children[1].target, "_blank");
  assert.equal(preview.children[1].rel, "noopener noreferrer");
  preview.children[0].handlers.error();
  assert.match(preview.children[0].textContent, /could not be rendered/);
  assert.deepEqual(revoked, ["blob:image-clue"]);
  imageContext.ui.renderArtifacts(true);
  const stale = resolveFetch;
  imageContext.ui.setSelected({id: "other", artifacts: []});
  imageContext.ui.renderArtifacts(true);
  stale({ok: true, blob: async () => ({type: "image/png"})});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(imageNodes.get("artifactGrid").children[0].children[1].textContent, "No artifacts yet");
  imageContext.ui.setSelected(imageState);
  imageContext.ui.renderArtifacts(true);
  resolveFetch({ok: false});
  await new Promise(resolve => setImmediate(resolve));
  const failure = imageNodes.get("artifactGrid").children[0].children.find(child => child.className === "artifact-image-wrap");
  assert.match(failure.children[0].textContent, /preview unavailable/);
  assert.match(html, /option value="image">Images/);
  console.log("Image UI checks passed: authenticated preview, full-size link, filter, stale response, rendering fallback, URL cleanup.");
})().catch(error => { console.error(error); process.exitCode = 1; });

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

context.ui.setReplay(null);
context.ui.renderDependencies({status: "warning", key: "wsl-kali", target: "WSL lab / peter", issues: ["Missing tools: whippet"], command: "python scripts/install_dependencies.py --runtime wsl --distro lab --user peter", tools: {bloodhound_collector: "bloodhound-python", certipy: "certipy-ad"}});
assert.match(nodes.get("dependencyDetected").textContent, /bloodhound-python \(legacy collector\)/);
assert.match(nodes.get("dependencyDetected").textContent, /certipy-ad/);
assert.match(nodes.get("dependencyResult").textContent, /Missing tools: whippet/);
nodes.get("dependencyWarning").handlers.click();
assert.equal(nodes.get("dependencyDialog").open, true);
assert.match(nodes.get("dependencyTarget").textContent, /WSL lab \/ peter/);
context.ui.renderDependencies({status: "installing", key: "wsl-kali", target: "WSL lab / peter", installation: {logs: ["Installing Whippet"]}});
assert.equal(nodes.get("dependencyDone").disabled, true);
assert.equal(nodes.get("dependencyInstall").disabled, true);
assert.equal(nodes.get("dependencyLog").textContent, "Installing Whippet");
context.ui.renderDependencies({status: "ready", key: "wsl-kali", target: "WSL lab / peter"});
assert.match(nodes.get("dependencyResult").textContent, /installed and verified/);
assert.equal(nodes.get("dependencyDone").disabled, false);
nodes.get("dependencyDone").handlers.click();
assert.equal(nodes.get("dependencyDialog").open, false);
context.ui.renderDependencies({status: "ready", key: "wsl-kali", target: "WSL lab / peter"});
assert.equal(nodes.get("dependencyDialog").open, false, "Polling must not reopen dependency setup after Done");
context.ui.renderDependencies({status: "warning", key: "wsl-kali", target: "WSL lab / peter", blocked: true});
assert.equal(nodes.get("dependencyInstall").disabled, true);
assert.match(fs.readFileSync("web/app.css", "utf8"), /dependency-result\.ready\{[^}]*#22c55e/);
console.log("Dependency UI checks passed: warning, focused dialog, progress, green success, Done dismissal, active-session guard.");

// A fresh browser/app instance must respect the persisted session acknowledgment.
const freshNodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
const freshDocument = {...document, documentElement: element(), getElementById: id => {
  assert(freshNodes.has(id)); return freshNodes.get(id);
}};
const freshContext = {...context, document: freshDocument};
delete freshContext.ui;
vm.createContext(freshContext);
vm.runInContext(source, freshContext);
const viewedSession = {...state, id: "previously-viewed", summary: {...state.summary, status: "finished", success: "yes"},
  success_viewed: true, flags: {"user.txt": {found: true}, "root.txt": {found: true}}};
freshContext.ui.setSelected(viewedSession);
freshContext.ui.renderSummary();
freshContext.ui.setSelected({...viewedSession, id: "another-viewed"});
freshContext.ui.renderSummary();
assert.equal(freshNodes.get("successDialog").opens, 0, "Previously viewed successes stay silent across instances and session switches");
freshContext.ui.setSelected({...viewedSession, id: "unseen-success", success_viewed: false});
freshContext.ui.renderSummary();
assert.equal(freshNodes.get("successDialog").opens, 1, "A newly seen success still celebrates");
freshContext.ui.renderSummary();
assert.equal(freshNodes.get("successDialog").opens, 1);
console.log("Persistent success UI checks passed: new instance, session switching, and unseen success.");

(async () => {
  const requests = [];
  const cacheContext = {...context, document: freshDocument, AbortController,
    sessionStorage: {getItem: key => key === "harpControlToken" ? "test-token" : null, setItem() {}},
    fetch: (url, options) => new Promise(resolve => requests.push({url, options, resolve}))};
  delete cacheContext.ui;
  vm.createContext(cacheContext);
  vm.runInContext(source, cacheContext);
  cacheContext.ui.setSelected(viewedSession);
  cacheContext.ui.cacheCompletedSession();
  cacheContext.ui.switchSession("uncached-session");
  assert.equal(requests.length, 1);
  cacheContext.ui.switchSession(viewedSession.id);
  assert.equal(requests.length, 2, "Click starts a request immediately instead of waiting for the polling timer");
  assert.equal(requests[0].options.signal.aborted, true);
  assert.equal(freshNodes.get("metricFlags").textContent, "2 / 2", "Cached completed-session metrics render before the request returns");
  requests[0].resolve({ok: true, json: async () => ({selected: {id: "stale"}})});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(freshNodes.get("metricFlags").textContent, "2 / 2", "Late responses cannot overwrite the selected session");
  await cacheContext.ui.poll();
  assert.equal(requests.length, 2, "An older request's cleanup cannot release a newer request's busy guard");
  cacheContext.ui.switchSession("third-session");
  assert.equal(requests.length, 3);
  assert.equal(requests[1].options.signal.aborted, true);
  console.log("Session switching checks passed: instant cached view, immediate fetch, abort, stale-response protection.");
})().catch(error => { console.error(error); process.exitCode = 1; });

// Stable keyed rows must retain hover/focus across polling, including large lists.
const manySessions = Array.from({length: 150}, (_, index) => ({id: `session-${index}`, status: "finished", mode: "hybrid", target: `lab-${index}`}));
context.ui.setSessions(manySessions);
context.ui.renderSessions();
const sidebar = nodes.get("sessionList");
assert.equal(sidebar.children.length, 150);
const originalRows = sidebar.children.slice();
const sidebarReplacements = sidebar.replacements;
context.ui.setSessions(manySessions.map(item => ({...item})));
context.ui.renderSessions();
assert.equal(sidebar.replacements, sidebarReplacements);
assert(originalRows.every((row, index) => row === sidebar.children[index]), "Polling must preserve hovered row elements");
context.ui.setSessions(manySessions.map((item, index) => ({...item, unseen_flags: index === 4 ? 1 : 0})));
context.ui.renderSessions();
assert.equal(sidebar.children[4], originalRows[4]);
assert.equal(sidebar.children[4].children[0].children[0].children[1].textContent, "!");
context.ui.setSessions(manySessions.slice(1));
context.ui.renderSessions();
assert.equal(sidebar.children[0], originalRows[1]);

const lru = new context.ui.SessionViewCache(3, 10000);
lru.set("a", {id: "a"}, true); lru.set("b", {id: "b"}, true); lru.set("c", {id: "c"}, true);
lru.get("a");
lru.set("d", {id: "d"}, true);
assert(!lru.has("b") && lru.has("a") && lru.has("c") && lru.has("d"), "Evict least recently viewed, not oldest-created");
lru.set("prefetch", {id: "prefetch"});
assert(!lru.has("prefetch"), "An unviewed background result must not displace viewed sessions");
lru.set("e", {id: "e"}, true, "c");
assert(lru.has("c"), "Selected session remains pinned");
const bounded = new context.ui.SessionViewCache(20, 150);
for (let index = 0; index < 50; index++) bounded.set(String(index), {value: "x".repeat(15)}, true);
assert(bounded.bytes <= 150 && bounded.entries.size <= 20, "Cache obeys its count and size budgets");
console.log("Large sidebar/LRU checks passed: stable rows, 150 sessions, viewed recency, pinned session, memory budget.");

// Confetti runs only on explicit dismissal and removes every particle afterward.
const confettiLayer = nodes.get("successConfetti");
const originalCreate = document.createElement;
const finishedAnimations = [];
document.createElement = () => {
  const piece = element();
  piece.remove = () => confettiLayer.removeChild(piece);
  piece.animate = (frames, options) => {
    assert(options.duration >= 1800 && options.duration <= 3000);
    assert.equal(frames[frames.length - 1].opacity, 0);
    return {finished: {then: finish => finishedAnimations.push(finish)}};
  };
  return piece;
};
nodes.get("successDialog").showModal();
nodes.get("closeSuccess").handlers.click();
assert.equal(nodes.get("successDialog").open, false);
assert.equal(confettiLayer.children.length, 90);
nodes.get("closeSuccess").handlers.click();
assert.equal(finishedAnimations.length, 90, "Repeated clicks on a closed dialog must not start another burst");
finishedAnimations.forEach(finish => finish());
assert.equal(confettiLayer.children.length, 0);
const originalMedia = context.matchMedia;
context.matchMedia = query => ({matches: query === "(prefers-reduced-motion: reduce)"});
nodes.get("successDialog").showModal();
nodes.get("closeSuccess").handlers.click();
assert.equal(confettiLayer.children.length, 0, "Reduced motion must disable confetti");
context.matchMedia = originalMedia;
document.createElement = originalCreate;
console.log("Confetti checks passed: explicit dismissal, single burst, particle cleanup, reduced motion.");

(async () => {
  let inFlight = 0, maximum = 0;
  const urls = [];
  const preloadNodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
  const preloadContext = {...context, document: {...document, documentElement: element(), getElementById: id => preloadNodes.get(id)},
    sessionStorage: {getItem: key => key === "harpControlToken" ? "test-token" : null, setItem() {}},
    fetch: async url => {
      urls.push(url); maximum = Math.max(maximum, ++inFlight);
      await new Promise(resolve => setImmediate(resolve));
      inFlight--;
      return {ok: true, json: async () => ({id: url.split("/")[3], summary: {status: "finished"}, events: [], success_viewed: false})};
    }};
  delete preloadContext.ui;
  vm.createContext(preloadContext); vm.runInContext(source, preloadContext);
  preloadContext.ui.setSessions(manySessions);
  await preloadContext.ui.prefetchRecentSessions();
  assert.equal(urls.length, 10);
  assert.equal(maximum, 2, "Startup prefetch uses only two concurrent requests");
  assert(urls.every(url => url.endsWith("/view")));
  assert.equal(preloadContext.ui.sessionCache.entries.size, 10);
  assert([...preloadContext.ui.sessionCache.entries.values()].every(entry => entry.viewed === 0));
  assert.equal(preloadNodes.get("successDialog").opens, 0, "Prefetch is not a view and must not acknowledge or celebrate success");
  await preloadContext.ui.prefetchRecentSessions();
  assert.equal(urls.length, 10, "Do not repeat startup prefetch every poll");
  console.log("Startup prefetch checks passed: ten sessions, bounded concurrency, no viewed acknowledgments.");
})().catch(error => { console.error(error); process.exitCode = 1; });
