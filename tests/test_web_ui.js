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
  "globalThis.ui = {interfaceSettings, applyInterfaceSettings, previewSettingsFile, restoreSettings, exportSettings, clearSnapshotPreview, renderArtifacts, SessionViewCache, sessionCache, prefetchRecentSessions, renderSessions, renderStartStop, switchSession, cacheCompletedSession, poll, renderDependencies, configPayload, renderSelections, renderSummary, renderElapsed, renderReplay, seekReplay, tickReplay, post, setStartPending(value) { startPending = value; }, setSessions(value) { sessions = value; }, setReplay(value) { replay = value; }, setSelected(value) { selected = value; }};"
);
assert(source.includes("globalThis.ui"), "Could not isolate UI rendering from network startup");
const storage = {getItem: () => null, setItem() {}};
const context = {document, localStorage: storage, sessionStorage: storage,
  setInterval() {}, requestAnimationFrame: () => 1, cancelAnimationFrame() {},
  performance: {now: () => 1000}, location: {hash: ""}, URLSearchParams,
  matchMedia: () => ({matches: false, addEventListener() {}})};
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
assert(html.indexOf('id="oracleSearch"') > html.indexOf('id="oracleAdaptive"'));
assert(html.indexOf('id="oracleSearch"') < html.indexOf('id="oracleReasoning"'));
assert(!/id="oracleSearch"[^>]*\bchecked/.test(html), "Search defaults off");
nodes.get("oracleSearch").checked = true;
for (const provider of ["codex", "zai", "openai", "nvidia_nim"]) {
  nodes.get("oracleProvider").value = provider;
  assert.equal(context.ui.configPayload().oracle.web_search_enabled, true);
}
nodes.get("oracleSearch").checked = false;
assert.equal(context.ui.configPayload().oracle.web_search_enabled, false);
console.log("Research UI checks passed: toggle beneath adaptive reasoning, defaults off, provider-independent persistence.");

(async () => {
  const backupNodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
  const values = new Map(), calls = [], downloaded = [], revoked = [];
  const cfg = JSON.parse(fs.readFileSync("harp.example.json", "utf8"));
  const preferences = {theme: "amoled", mode: "frontier-only", replay_speed: "8", replay_skip_idle: false, fresh_recon: true, api_key_provider: "zai"};
  const snapshot = {format: "harp-settings", version: 1, created_at: "2026-11-08T12:00:00+00:00", config: cfg, ui: preferences};
  class BackupURL extends URL {}
  BackupURL.createObjectURL = () => "blob:settings-backup";
  BackupURL.revokeObjectURL = url => revoked.push(url);
  const backupContext = {...context, URL: BackupURL, Blob, setTimeout: fn => { fn(); }, clearTimeout() {},
    Option: function(text, value) { return {...element(), textContent: text, value}; },
    localStorage: {getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key)},
    sessionStorage: {getItem: () => "test-control-token", setItem() {}},
    document: {...document, documentElement: element(), getElementById: id => backupNodes.get(id),
      createElement: tag => ({...element(), click() { if (tag === "a") downloaded.push(this.download); }})},
    fetch: async (url, options = {}) => {
      calls.push({url, body: options.body && JSON.parse(options.body)});
      assert.equal(options.headers["X-HARP-Token"], "test-control-token");
      const result = url === "/api/settings/export" ? {snapshot} : url === "/api/settings/preview" ? {preview: {
        created_at: snapshot.created_at, target: "target", runtime: "docker", oracle: cfg.oracle, proxy: cfg.local, ui: preferences, included_key_providers: []}} :
        url === "/api/settings/apply" ? {config: {...cfg, ui: preferences}, ui: preferences, recovery_id: "a".repeat(32)} :
        url === "/api/settings/recovery" ? {snapshot} :
        {config: cfg, sessions: [], selected: null, keys: {}, model: {logs: []}, dependencies: {status: "ready", issues: []}};
      return {ok: true, json: async () => result};
    }};
  delete backupContext.ui;
  vm.createContext(backupContext); vm.runInContext(source, backupContext);
  await backupContext.ui.exportSettings();
  assert.equal(calls[0].body.include_keys, false);
  assert(downloaded[0].startsWith("harp-settings-"));
  assert.deepEqual(revoked, ["blob:settings-backup"]);
  const beforeInvalid = calls.length;
  await backupContext.ui.previewSettingsFile({size: 3, text: async () => "bad"});
  assert.equal(calls.length, beforeInvalid, "Invalid JSON must not be posted");
  await backupContext.ui.previewSettingsFile({size: 50000, text: async () => "{}"});
  assert.equal(calls.length, beforeInvalid, "Oversized files must not be posted");
  await backupContext.ui.previewSettingsFile({size: 2000, text: async () => JSON.stringify(snapshot)});
  assert.equal(calls[calls.length - 1].url, "/api/settings/preview");
  assert(!calls.some(call => call.url === "/api/settings/apply"), "Choosing a backup must not apply it");
  assert.match(backupNodes.get("snapshotPreview").textContent, /Theme: amoled/);
  await backupContext.ui.restoreSettings();
  assert.equal(calls.find(call => call.url === "/api/settings/apply").body.restore_keys, false);
  assert.equal(backupNodes.get("modeSelect").value, "frontier-only");
  assert.equal(backupNodes.get("replaySpeed").value, "8");
  assert.equal(backupContext.document.documentElement.dataset.theme, "amoled");
  assert.equal(JSON.parse(values.get("harpUiSettings")).api_key_provider, "zai");
  assert(!calls.some(call => /sessions\/start|model\/start/.test(call.url)), "Restoring cannot start work");
  const afterApply = calls.length;
  await backupContext.ui.restoreSettings();
  assert.equal(calls.length, afterApply, "Applied snapshot must be released from memory");
  await backupNodes.get("snapshotRecovery").handlers.click();
  assert(downloaded[1].startsWith("harp-settings-before-restore-"));
  console.log("Snapshot UI checks passed: export, preview before apply, invalid files, preference restoration, recovery download, no automatic execution.");
})().catch(error => { console.error(error); process.exitCode = 1; });

context.ui.setReplay(null);
context.ui.renderDependencies({status: "warning", key: "wsl-kali", target: "WSL lab / peter", issues: ["Missing tools: whippet"], command: "python scripts/install_dependencies.py --runtime wsl --distro lab --user peter", tools: {bloodhound_collector: "bloodhound-python", certipy: "certipy-ad"}});
assert.match(nodes.get("dependencyDetected").textContent, /bloodhound-python \(legacy collector\)/);
assert.match(nodes.get("dependencyDetected").textContent, /certipy-ad/);
assert.match(nodes.get("dependencyResult").textContent, /Missing tools: whippet/);
context.ui.renderDependencies({status: "warning", runtime: "native", key: "native", target: "Native Kali / current user", issues: ["Missing tools: whippet"], command: "sudo -v && python3 scripts/install_dependencies.py --runtime native"});
assert.match(nodes.get("dependencyAuth").textContent, /system authentication dialog/);
assert.match(nodes.get("dependencyCommand").textContent, /sudo -v/);
context.ui.renderDependencies({status: "warning", key: "wsl-kali", target: "WSL lab / peter", issues: ["Missing tools: whippet"], command: "python scripts/install_dependencies.py --runtime wsl --distro lab --user peter", tools: {bloodhound_collector: "bloodhound-python", certipy: "certipy-ad"}});
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
context.ui.setSessions(manySessions.map((item, index) => ({...item, imported: index === 4})));
context.ui.renderSessions();
assert.equal(sidebar.children[4].children[0].children[0].children[0].textContent, "lab-4 (upload)");
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
context.ui.applyInterfaceSettings({animation_mode: "off"});
nodes.get("successDialog").showModal();
nodes.get("closeSuccess").handlers.click();
assert.equal(confettiLayer.children.length, 0, "Off must disable confetti");
context.ui.applyInterfaceSettings({animation_mode: "on"});
context.matchMedia = originalMedia;
document.createElement = originalCreate;
console.log("Confetti checks passed: explicit dismissal, single burst, particle cleanup, animation preference.");

// Exercise actual animation frames, including Windows' reduced-motion setting.
{
  const motionNodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(x => [x[1], element()]));
  const rings = Array.from({length: 3}, () => ({style: {}}));
  const frames = new Map(), mediaHandlers = {}, stored = new Map();
  let clock = 1000, nextFrame = 0;
  const systemMotion = {matches: true, addEventListener(name, handler) { mediaHandlers[name] = handler; }};
  const motionContext = {...context,
    document: {...document, documentElement: element(), getElementById: id => motionNodes.get(id),
      querySelectorAll: selector => selector === ".hero-graphic .orbit" ? rings : [],
      createElement: () => {
        const piece = element();
        piece.remove = () => motionNodes.get("successConfetti").removeChild(piece);
        piece.animate = () => ({finished: new Promise(() => {})});
        return piece;
      }},
    localStorage: {getItem: key => stored.get(key) || null, setItem: (key, value) => stored.set(key, value)},
    performance: {now: () => clock},
    requestAnimationFrame: callback => { frames.set(++nextFrame, callback); return nextFrame; },
    cancelAnimationFrame: id => frames.delete(id),
    matchMedia: query => query === "(prefers-reduced-motion: reduce)" ? systemMotion : {matches: false}};
  delete motionContext.ui;
  vm.createContext(motionContext); vm.runInContext(source, motionContext);
  const tick = () => { clock += 100; const pending = [...frames.values()]; frames.clear(); pending.forEach(fn => fn(clock)); };
  motionContext.ui.setStartPending(true);
  motionContext.ui.renderStartStop();
  assert.equal(frames.size, 1, "Live startup schedules animation even when OS animations are off");
  tick();
  const initial = rings.map(ring => ring.style.transform);
  tick();
  assert(rings.every((ring, i) => ring.style.transform !== initial[i]), "Every live orbit moves");
  motionContext.ui.setStartPending(false);
  for (const status of ["recon", "active"]) {
    motionContext.ui.setSessions([{id: "live", status}]);
    motionContext.ui.renderStartStop();
    assert.equal(frames.size, 1, "Polling retains one animation loop during " + status);
    tick();
  }
  motionNodes.get("successDialog").showModal();
  motionNodes.get("closeSuccess").handlers.click();
  assert.equal(motionNodes.get("successConfetti").children.length, 90, "Default On restores confetti with OS reduced motion");
  motionContext.ui.applyInterfaceSettings({animation_mode: "system"});
  assert.equal(frames.size, 0, "Follow system stops live motion when reduced motion is requested");
  assert.equal(motionNodes.get("successConfetti").children.length, 0);
  motionNodes.get("successDialog").showModal(); motionNodes.get("closeSuccess").handlers.click();
  assert.equal(motionNodes.get("successConfetti").children.length, 0, "Follow system also disables confetti");
  systemMotion.matches = false; mediaHandlers.change();
  assert.equal(frames.size, 1, "Follow system responds to preference changes");
  motionContext.ui.setSessions([{id: "live", status: "finished"}]); motionContext.ui.renderStartStop();
  assert.equal(frames.size, 0, "Completion stops live orbits");
  const playback = {loading: false, playing: true, seconds: 5, lastTick: clock, duration_seconds: 100};
  motionContext.ui.setReplay(playback);
  motionContext.ui.applyInterfaceSettings({animation_mode: "on"});
  assert.equal(frames.size, 1, "Replay schedules only its own animation loop");
  tick();
  const playing = rings[0].style.transform;
  playback.seconds += 2; tick();
  assert.notEqual(rings[0].style.transform, playing, "Replay orbits move");
  playback.playing = false; motionContext.ui.applyInterfaceSettings({animation_mode: "on"});
  assert.equal(frames.size, 0, "Paused replay has no animation loop");
  playback.playing = true; motionContext.ui.applyInterfaceSettings({animation_mode: "off"});
  assert.equal(frames.size, 0, "Off disables replay as well as live motion");
  assert.equal(JSON.parse(stored.get("harpUiSettings")).animation_mode, "off", "Preference persists");
  assert.equal(motionContext.ui.interfaceSettings().animation_mode, "off", "Snapshots include animation preference");
  assert(!fs.readFileSync("web/app.css", "utf8").includes(".confetti-layer{display:none}"), "CSS must not silently override explicit On");
  console.log("Animation checks passed: live startup/recon/active frames, OS override, confetti, replay, pause, system preference, persistence.");
}

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
