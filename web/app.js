(() => {
  "use strict";

  const $ = id => document.getElementById(id);
  const tokenFromUrl = new URLSearchParams(location.hash.slice(1)).get("token");
  if (tokenFromUrl) {
    sessionStorage.setItem("harpControlToken", tokenFromUrl);
    history.replaceState(null, "", location.pathname + location.search);
  }
  const token = sessionStorage.getItem("harpControlToken") || "";
  let currentPage = "overview";
  let replay = null;
  let selectedId = localStorage.getItem("harpSelectedSession") || "";
  let selected = null;
  let sessions = [];
  let cursor = 0;
  let modelCursor = 0;
  let lastModel = null;
  let budgetSessionId = "";
  let currentFilter = "all";
  let artifactSignature = "";
  let pendingSnapshot = null;
  let snapshotRecoveryId = "";
  let snapshotBusy = false;
  let archiveBusy = false;
  let artifactGeneration = 0;
  const artifactImageUrls = new Set();
  let configLoaded = false;
  let pollBusy = false;
  let pollController = null;
  class SessionViewCache {
    constructor(maxEntries = 20, maxBytes = 32_000_000) {
      this.maxEntries = maxEntries; this.maxBytes = maxBytes;
      this.entries = new Map(); this.bytes = 0; this.clock = 0;
    }
    has(id) { return this.entries.has(id); }
    get(id) {
      const entry = this.entries.get(id);
      if (!entry) return null;
      entry.viewed = ++this.clock;
      return entry.value;
    }
    delete(id) {
      const entry = this.entries.get(id);
      if (entry) { this.bytes -= entry.bytes; this.entries.delete(id); }
    }
    set(id, value, viewed = false, pinned = "") {
      const bytes = JSON.stringify(value).length * 2;
      if (bytes > this.maxBytes) return;
      const previous = this.entries.get(id);
      const rank = viewed ? ++this.clock : previous?.viewed || 0;
      this.delete(id);
      this.entries.set(id, {value, bytes, viewed: rank}); this.bytes += bytes;
      while (this.entries.size > this.maxEntries || this.bytes > this.maxBytes) {
        const candidates = [...this.entries].filter(([key]) => key !== pinned);
        if (!candidates.length) break;
        const victim = candidates.reduce((a, b) => a[1].viewed <= b[1].viewed ? a : b);
        this.delete(victim[0]);
      }
    }
  }
  const sessionCache = new SessionViewCache();
  const sessionRows = new Map();
  let sessionListEmpty = false;
  let startupPrefetchStarted = false;
  let startPending = false;
  let startingAt = null;
  let verboseEvents = [];
  let seenPending = false;
  let toastTimer;
  let reviewDialogShownId = "";
  let dependencies = null;
  let dependencyPending = false;
  const celebratedSessions = new Set();
  const successAcknowledgments = new Set();
  const orbitRings = [...document.querySelectorAll(".hero-graphic .orbit")];
  const orbitStartAngles = [36, -112, 142];
  const orbitAngles = [...orbitStartAngles];
  const orbitDirections = [1, -0.78, 1.18];
  const reducedOrbitMotion = matchMedia("(prefers-reduced-motion: reduce)");
  let animationMode = "on";
  let orbitRunning = false;
  let orbitStartedAt = 0;
  let orbitLastFrame = 0;
  let orbitFrame = 0;
  let replayOrbitFrame = 0;

  function animationsEnabled() {
    return animationMode === "on" || (animationMode === "system" && !reducedOrbitMotion.matches);
  }

  function syncAnimations() {
    $("animationMode").value = animationMode;
    if (!animationsEnabled()) $("successConfetti").replaceChildren();
    if (replay) renderReplayOrbits(replay.seconds);
    syncReplayOrbitMotion();
    setOrbitRunning(!replay && (startPending || sessions.some(session =>
      session.status === "active" || session.status === "recon")));
  }

  function easeOrbit(value) {
    const t = Math.max(0, Math.min(1, value));
    return t * t * (3 - 2 * t);
  }

  function orbitSpeed(seconds) {
    if (seconds < 1.25) return 210 * easeOrbit(seconds / 1.25);
    if (seconds < 4.25) return 210 + (22 - 210) * easeOrbit((seconds - 1.25) / 3);
    return 22;
  }

  function orbitTravel(seconds) {
    const t = Math.max(0, seconds);
    const smoothArea = value => value ** 3 - 0.5 * value ** 4;
    if (t < 1.25) return 210 * 1.25 * smoothArea(t / 1.25);
    const burst = 210 * 1.25 / 2;
    if (t < 4.25) {
      const deceleration = t - 1.25;
      return burst + 210 * deceleration - 188 * 3 * smoothArea(deceleration / 3);
    }
    return burst + (210 - 188 / 2) * 3 + 22 * (t - 4.25);
  }

  function renderReplayOrbits(seconds) {
    const travel = animationsEnabled() ? orbitTravel(seconds) : 0;
    orbitRings.forEach((ring, index) => {
      orbitAngles[index] = (orbitStartAngles[index] + travel * orbitDirections[index]) % 360;
      ring.style.transform = `rotate(${orbitAngles[index]}deg)`;
    });
  }

  function replayOrbitTick(now) {
    if (!replay || replay.loading || !replay.playing || !animationsEnabled()) {
      replayOrbitFrame = 0;
      return;
    }
    const ahead = Math.min(Math.max(0, (now - replay.lastTick) / 1000), 0.1);
    const seconds = Math.min(replay.duration_seconds,
      replay.seconds + ahead * Number($("replaySpeed").value || 1));
    renderReplayOrbits(seconds);
    replayOrbitFrame = requestAnimationFrame(replayOrbitTick);
  }

  function syncReplayOrbitMotion() {
    if (replayOrbitFrame) cancelAnimationFrame(replayOrbitFrame);
    replayOrbitFrame = 0;
    if (replay && !replay.loading && replay.playing && animationsEnabled())
      replayOrbitFrame = requestAnimationFrame(replayOrbitTick);
  }

  function orbitTick(now) {
    if (!orbitRunning || !animationsEnabled()) return;
    const elapsed = (now - orbitStartedAt) / 1000;
    const delta = Math.min((now - orbitLastFrame) / 1000, 0.1);
    orbitLastFrame = now;
    const advance = orbitSpeed(elapsed) * Math.max(0, delta);
    orbitRings.forEach((ring, index) => {
      orbitAngles[index] = (orbitAngles[index] + advance * orbitDirections[index]) % 360;
      ring.style.transform = `rotate(${orbitAngles[index]}deg)`;
    });
    orbitFrame = requestAnimationFrame(orbitTick);
  }

  function setOrbitRunning(running) {
    if (!animationsEnabled()) running = false;
    if (running === orbitRunning) return;
    orbitRunning = running;
    if (orbitFrame) cancelAnimationFrame(orbitFrame);
    orbitFrame = 0;
    if (running) {
      orbitStartedAt = orbitLastFrame = performance.now();
      orbitFrame = requestAnimationFrame(orbitTick);
    }
  }

  reducedOrbitMotion.addEventListener("change", syncAnimations);

  function acknowledgeSuccess(session) {
    if (!token || replay || session.success_viewed || successAcknowledgments.has(session.id)) return;
    successAcknowledgments.add(session.id);
    post(`/api/sessions/${encodeURIComponent(session.id)}/success-viewed`)
      .then(() => { session.success_viewed = true; })
      .catch(() => {}) // Polling retries if acknowledgment could not be saved.
      .finally(() => successAcknowledgments.delete(session.id));
  }

  function renderDependencies(value) {
    dependencies = value || null;
    const state = value?.status || "checking";
    const busy = state === "installing" || dependencyPending;
    const ready = state === "ready";
    $("dependencyWarning").classList.toggle("hidden", !value || ready);
    $("dependencyWarningTitle").textContent = busy ? "Installing Kali dependencies" : state === "checking" ? "Checking Kali dependencies" : "Kali dependencies need attention";
    $("dependencyWarningDetail").textContent = value ? `${value.target} · Open setup` : "";
    $("dependencyTarget").textContent = value ? `Saved runtime: ${value.target}. Save Configuration to change it.` : "Waiting for runtime configuration.";
    const detected = Object.entries(value?.tools || {}).filter(([, name]) => name).map(([tool, name]) => `${tool.replaceAll("_", " ")}: ${name}${name === "bloodhound-python" ? " (legacy collector)" : name === "enum4linux" ? " (legacy tool; enum4linux-ng is separate)" : ""}`);
    $("dependencyDetected").textContent = detected.length ? `Detected AD tools: ${detected.join("; ")}` : "";
    $("dependencyTitle").textContent = ready ? "Dependencies ready" : busy ? "Installing dependencies" : "Set up your Kali tools";
    $("dependencyResult").classList.toggle("ready", ready);
    $("dependencyResult").classList.toggle("warning", state === "warning");
    $("dependencyResult").textContent = ready ? "Dependencies installed and verified. You're ready to start a session."
      : busy ? "Installing tools and running checks. This can take several minutes."
      : state === "checking" || value?.checking ? "Checking installed tools. No target is contacted."
      : (value?.issues || []).join("\n");
    $("dependencyBlocked").textContent = value?.blocked ? "Stop active sessions before installing dependencies." : "";
    $("dependencyAuth").classList.toggle("hidden", value?.runtime !== "native" || ready);
    $("dependencyAuth").textContent = value?.runtime === "native" && !ready
      ? "Native Kali: Install opens a system authentication dialog for apt packages. Enter your administrator password there. If no dialog appears, run the command below in a Kali terminal."
      : "";
    $("dependencyCommand").textContent = value?.command || "Choose and save a runtime in Configuration first.";
    $("dependencyLog").textContent = (value?.installation?.logs || []).join("\n");
    $("dependencyOutput").classList.toggle("hidden", !(value?.installation?.logs || []).length);
    $("dependencyInstall").disabled = busy || !!replay || !!value?.blocked || !!value?.checking || state === "checking" || !value?.key;
    $("dependencyInstall").textContent = busy ? "Installing…" : ready ? "Reinstall dependencies" : "Install dependencies";
    $("dependencyInstall").classList.toggle("hidden", ready);
    $("dependencyDone").classList.toggle("primary", ready);
    $("dependencyDone").classList.toggle("ghost", !ready);
    $("dependencyRecheck").disabled = busy || !!replay || !!value?.checking || state === "checking";
    $("dependencyDone").disabled = busy;
  }

  function openApprovalDialog(approval) {
    if (!approval || $("rootDialog").open) return;
    const check = approval.source === "command_check";
    $("dialogTitle").textContent = check ? "Review flagged command?" : "Authorize root command?";
    $("dialogDescription").textContent = check
      ? `HARP flagged this command: ${approval.reason} Approving runs the exact command in the selected Kali runtime. Review time does not count against the proxy model.`
      : "The exact command below will run as root in the selected Kali runtime. Permission does not count as tactical help.";
    $("dialogCommand").textContent = approval.command;
    $("confirmRoot").textContent = check ? "Accept and run" : "Authorize command";
    $("rootDialog").showModal();
  }

  const themes = ["light", "dark", "amoled"];
  const themeLabels = { light: "Light", dark: "Dark", amoled: "AMOLED Dark" };
  const themeIcons = { light: "\u2600", dark: "\u263e", amoled: "\u25cf" };
  const savedTheme = localStorage.getItem("harpTheme");
  const preferredTheme = themes.includes(savedTheme) ? savedTheme : (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $("themeIcon").textContent = themeIcons[theme];
    const next = themes[(themes.indexOf(theme) + 1) % themes.length];
    const label = `${themeLabels[theme]} theme. Switch to ${themeLabels[next]}`;
    $("themeToggle").title = label;
    $("themeToggle").setAttribute("aria-label", label);
  }

  applyTheme(preferredTheme);

  function interfaceSettings() {
    return {theme: document.documentElement.dataset.theme, mode: $("modeSelect").value || "hybrid",
      animation_mode: animationMode,
      replay_speed: $("replaySpeed").value || "1", replay_skip_idle: !!$("replaySkipIdle").checked,
      fresh_recon: !!$("freshRecon").checked, api_key_provider: $("apiKeyProvider").value || "openai"};
  }

  function rememberInterfaceSettings() {
    localStorage.setItem("harpUiSettings", JSON.stringify(interfaceSettings()));
    localStorage.setItem("harpTheme", document.documentElement.dataset.theme);
  }

  function applyInterfaceSettings(value) {
    if (!value || typeof value !== "object") return;
    if (themes.includes(value.theme)) applyTheme(value.theme);
    if (["on", "system", "off"].includes(value.animation_mode)) animationMode = value.animation_mode;
    if (["hybrid", "local-only", "frontier-only"].includes(value.mode)) $("modeSelect").value = value.mode;
    if (["1", "2", "4", "8", "16", "32"].includes(value.replay_speed)) $("replaySpeed").value = value.replay_speed;
    if (typeof value.replay_skip_idle === "boolean") $("replaySkipIdle").checked = value.replay_skip_idle;
    if (typeof value.fresh_recon === "boolean") $("freshRecon").checked = value.fresh_recon;
    if (["openai", "zai", "nvidia_nim", "unsloth"].includes(value.api_key_provider)) $("apiKeyProvider").value = value.api_key_provider;
    syncAnimations();
    rememberInterfaceSettings();
  }

  function downloadSettings(snapshot, label = "harp-settings") {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${label}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  function clearSnapshotPreview() {
    pendingSnapshot = null;
    $("snapshotRestorePanel").classList.add("hidden");
    $("snapshotPreview").textContent = "";
    $("snapshotDetails").textContent = "";
    $("snapshotRestoreKeys").checked = false;
    $("snapshotFile").value = "";
  }

  function setSnapshotBusy(value) {
    snapshotBusy = value;
    for (const id of ["snapshotExport", "snapshotFile", "snapshotApply", "snapshotCancel", "snapshotIncludeKeys", "snapshotRestoreKeys"])
      $(id).disabled = value;
  }

  async function exportSettings() {
    if (snapshotBusy) return;
    setSnapshotBusy(true);
    try {
      const result = await post("/api/settings/export", {ui: interfaceSettings(), include_keys: !!$("snapshotIncludeKeys").checked});
      downloadSettings(result.snapshot);
      $("snapshotStatus").textContent = "Saved settings exported.";
    } catch (error) { $("snapshotStatus").textContent = error.message; }
    finally { setSnapshotBusy(false); }
  }

  async function previewSettingsFile(file) {
    if (snapshotBusy) return;
    clearSnapshotPreview();
    if (!file) return;
    setSnapshotBusy(true);
    try {
      if (file.size > 48 * 1024) throw new Error("Settings snapshot exceeds 48 KiB.");
      const snapshot = JSON.parse(await file.text());
      const result = await post("/api/settings/preview", {snapshot});
      const info = result.preview;
      $("snapshotDetails").textContent = JSON.stringify({config: snapshot.config, ui: info.ui}, null, 2);
      $("snapshotPreview").textContent = `Created: ${info.created_at}\nTarget: ${info.target || "Not selected"}\nRuntime: ${info.runtime}\nOracle: ${info.oracle.provider || "codex"} / ${info.oracle.model || "Current Codex session"}\nProxy: ${info.proxy.provider || "unsloth"} / ${info.proxy.model || "Not selected"}\nAdaptive reasoning: ${info.oracle.adaptive_reasoning === true ? "on" : "off"}\nWeb search: ${info.oracle.web_search_enabled === true ? "on" : "off"}\nTheme: ${info.ui.theme}\nExperiment mode: ${info.ui.mode}\nIncluded API keys: ${info.included_key_providers.join(", ") || "none"}`;
      $("snapshotRestoreKeysLabel").classList.toggle("hidden", !info.included_key_providers.length);
      $("snapshotRestorePanel").classList.remove("hidden");
      $("snapshotStatus").textContent = "Backup validated. Review the settings, then apply when ready.";
      pendingSnapshot = snapshot;
    } catch (error) { $("snapshotStatus").textContent = error instanceof SyntaxError ? "Choose a valid JSON settings backup." : error.message; }
    finally { setSnapshotBusy(false); }
  }

  async function restoreSettings() {
    if (snapshotBusy || !pendingSnapshot) return;
    setSnapshotBusy(true);
    try {
      const result = await post("/api/settings/apply", {snapshot: pendingSnapshot,
        current_ui: interfaceSettings(), restore_keys: !!$("snapshotRestoreKeys").checked});
      applyInterfaceSettings(result.ui);
      configLoaded = false;
      fillConfig(result.config);
      renderSelections();
      if (lastModel) renderModel({...lastModel, logs: []});
      snapshotRecoveryId = result.recovery_id;
      $("snapshotRecovery").classList.remove("hidden");
      clearSnapshotPreview();
      $("snapshotStatus").textContent = "Settings restored. A pre-restore backup is available below. No model or session was started.";
      await poll();
    } catch (error) { $("snapshotStatus").textContent = error.message; }
    finally { setSnapshotBusy(false); }
  }

  function toast(message, error = false) {
    const node = $("toast");
    node.textContent = message;
    node.classList.toggle("error", error);
    node.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add("hidden"), 4500);
  }

  async function api(path, options = {}) {
    if (!token) throw new Error("Open the private URL printed by the Python launcher.");
    const response = await fetch(path, {
      ...options,
      cache: "no-store",
      headers: {"X-HARP-Token": token, ...(options.body ? {"Content-Type": "application/json"} : {}), ...(options.headers || {})}
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }

  const post = (path, body = {}) => {
    if (replay) throw new Error("Exit recorded replay before making changes.");
    return api(path, {method: "POST", body: JSON.stringify(body)});
  };
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const formatTime = value => value ? new Date(value).toLocaleString() : "—";
  const formatDuration = seconds => {
    const total = Math.max(0, Math.floor(seconds || 0));
    const h = Math.floor(total / 3600), m = Math.floor(total % 3600 / 60), s = total % 60;
    return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
  };

  function switchSession(id) {
    if (!id || (id === selectedId && !replay)) return;
    if (replay) exitReplay(false);
    if (pollController) pollController.abort();
    pollController = null;
    pollBusy = false;
    selectedId = id;
    localStorage.setItem("harpSelectedSession", id);
    selected = null;
    cursor = 0;
    artifactSignature = "";
    $("activityFeed").replaceChildren();
    verboseEvents = [];
    $("verboseFeed").replaceChildren();
    $("objectiveInput").value = "";
    const cached = sessionCache.get(id);
    if (cached) {
      selected = cached.selected;
      cursor = cached.cursor;
      appendEvents(cached.events);
      renderSummary();
    } else renderSummary();
    renderSessions();
    renderStartStop();
    poll();
  }

  function cacheCompletedSession() {
    if (!selected || selected.summary.status !== "finished") return;
    storeSessionView(selected, verboseEvents, cursor, true);
  }

  function storeSessionView(view, events = [], nextCursor = 0, viewed = false) {
    const snapshot = {selected: {...view, events: []}, cursor: nextCursor, events: events.slice()};
    // Keep the overview even when terminal history exceeds the per-entry budget.
    if (JSON.stringify(snapshot).length > 1_000_000) { snapshot.events = []; snapshot.cursor = 0; }
    if (JSON.stringify(snapshot).length > 1_000_000) return;
    sessionCache.set(view.id, snapshot, viewed, selectedId);
  }

  async function prefetchRecentSessions() {
    if (startupPrefetchStarted || !sessions.length || !token || replay) return;
    startupPrefetchStarted = true;
    const queue = sessions.filter(session => session.status === "finished").slice(0, 10);
    let index = 0;
    const worker = async () => {
      while (index < queue.length) {
        const session = queue[index++];
        if (sessionCache.has(session.id) || session.id === selectedId) continue;
        try {
          const view = await api(`/api/sessions/${encodeURIComponent(session.id)}/view`);
          if (!replay && view.id === session.id && view.summary.status === "finished"
              && session.id !== selectedId && !sessionCache.has(session.id)
              && sessions.some(item => item.id === session.id)) storeSessionView(view);
        } catch (_) { /* Selecting retries normally; prefetch never opens dialogs. */ }
      }
    };
    await Promise.all([worker(), worker()]);
  }

  function showPage(name) {
    if (!replay && name === "flags" && selected && !Object.values(selected.flags || {}).some(x => x.unseen)) {
      const unseenSession = sessions.find(s => s.unseen_flags > 0);
      if (unseenSession && unseenSession.id !== selectedId) switchSession(unseenSession.id);
    }
    currentPage = name;
    document.querySelectorAll(".page").forEach(page => page.classList.toggle("active", page.dataset.panel === name));
    document.querySelectorAll(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.page === name));
    $("pageCrumb").textContent = ({overview: "Overview", verbose: "Verbose", flags: "Flags", artifacts: "Artifacts", model: "Proxy model", oracle: "Oracle model", keys: "API Keys", settings: "Configuration"})[name];
    if (name === "verbose") renderVerbose();
    if (name === "flags") acknowledgeFlags();
    if (name === "artifacts") renderArtifacts(true);
  }

  function renderSessions() {
    const list = $("sessionList");
    const ids = new Set(sessions.map(session => session.id));
    for (const [id, record] of sessionRows) if (!ids.has(id)) {
      list.removeChild(record.row); sessionRows.delete(id); sessionCache.delete(id);
    }
    if (!sessions.length) {
      if (!sessionListEmpty) list.replaceChildren(el("div", "empty-small", "No sessions yet"));
      sessionListEmpty = true;
      return;
    }
    if (sessionListEmpty || !sessionRows.size) list.replaceChildren();
    sessionListEmpty = false;
    const text = (node, value) => { if (node.textContent !== value) node.textContent = value; };
    for (const [index, session] of sessions.entries()) {
      let record = sessionRows.get(session.id);
      if (!record) {
        const row = el("div", "session-row"), button = el("button", "session-item"), top = el("div", "session-top");
        button.type = "button";
        const target = el("span"), marker = el("span", "session-mini-alert"), sub = el("div", "session-sub");
        top.append(target, marker); button.append(top, sub); row.append(button);
        button.addEventListener("click", () => switchSession(session.id));
        record = {row, button, target, marker, sub, remove: null};
        sessionRows.set(session.id, record);
      }
      record.row.classList.toggle("selected", session.id === selectedId);
      text(record.target, session.target + (session.imported ? " (upload)" : ""));
      const marker = session.pending_approval ? "!" : session.unseen_flags ? "!" : session.flags_found ? "\u2713" : "";
      text(record.marker, marker);
      text(record.sub, `${session.mode} \u00b7 ${session.status} \u00b7 ${session.id.slice(9,15)}`);
      if (session.status === "finished" && !record.remove) {
        const remove = el("button", "session-delete", "x");
        remove.type = "button";
        remove.title = "Delete session and logs";
        remove.setAttribute("aria-label", `Delete session and logs for ${session.target}`);
        remove.addEventListener("click", () => {
          const current = sessions.find(item => item.id === session.id);
          if (current) deleteFinishedSession(current);
        });
        record.row.append(remove); record.remove = remove;
      } else if (session.status !== "finished" && record.remove) {
        record.row.removeChild(record.remove); record.remove = null;
      }
      if (list.children[index] !== record.row) list.insertBefore(record.row, list.children[index] || null);
    }
  }

  function renderStartStop() {
    const active = sessions.find(session => session.id === selectedId && session.status === "active") ||
                   sessions.find(session => session.status === "active");
    const recon = sessions.find(session => session.status === "recon");
    const running = active || recon;
    setOrbitRunning(!replay && (startPending || !!running));
    const button = $("startSession");
    if (running) startPending = false;
    button.classList.toggle("danger", !!running);
    button.classList.toggle("primary", !running);
    button.replaceChildren(document.createTextNode(running ? "■ Stop session" : startPending ? "Starting session…" : "＋ Start session"));
    button.disabled = !!replay || (startPending && !running) || (dependencies?.status === "installing" && !running);
    $("replayStart").disabled = !!replay || selected?.summary.status !== "finished";
    $("saveSession").disabled = archiveBusy || !!replay || selected?.summary.status !== "finished";
    $("importSession").disabled = archiveBusy || !!replay;
    button.dataset.stopId = running?.id || "";
    $("modeSelect").disabled = !!replay || !!running;
  }

  function deleteFinishedSession(session) {
    if (session.status !== "finished") return;
    if (!confirm(`Permanently delete session ${session.id}, including logs, artifacts, and captured files?`)) return;
    action(`/api/sessions/${encodeURIComponent(session.id)}/delete`);
  }

  function renderSelections() {
    $("oracleReasoning").disabled = $("oracleAdaptive").checked && ["zai", "openai"].includes($("oracleProvider").value);
    const providers = {openai: "OpenAI", zai: "Z.AI", nvidia_nim: "NVIDIA NIM", unsloth: "Unsloth", codex: "Codex via MCP"};
    for (const [role, label, modelId] of [["oracle", "Oracle", "oracleModel"], ["proxy", "Proxy", "proxyNimModel"]]) {
      const provider = $(role + "Provider").value;
      const access = provider === "openai" ? ` / ${$(role + "Access").value === "daybreak_blue" ? "Daybreak Blue" : "Standard"}` : "";
      $(role === "oracle" ? "sidebarOracleProvider" : "sidebarProxyProvider").textContent = `${label} / ${providers[provider] || "Not selected"}${access}`;
      const model = provider === "codex" ? "Current Codex session" : provider === "unsloth" ? $("studioModel").value.trim() : $(modelId).value;
      const node = $(role === "oracle" ? "sidebarOracleModel" : "sidebarProxyModel");
      node.textContent = model || "No model selected";
      node.title = model || "No model selected";
    }
  }

  $("oracleAdaptive").addEventListener("change", renderSelections);

  function renderCostSummary(sum = {}) {
    const money = value => value == null ? "Estimate unavailable" : `$${value.toFixed(6)}`;
    const hasCalls = (sum.oracle_model_calls || 0) + (sum.local_model_calls || 0) > 0;
    $("totalApiCost").textContent = hasCalls ? money(sum.total_estimated_usd) : "No calls yet";
    const comparable = sum.cost_comparison_status === "same_workload_estimate";
    const unavailable = sum.cost_comparison_status === "missing_prices_or_usage" ? "Check token prices and usage" : "Requires Hybrid proxy usage";
    $("oracleOnlyCost").textContent = comparable ? money(sum.oracle_only_estimated_usd) : unavailable;
    $("hybridSavings").textContent = comparable ? (sum.hybrid_savings_usd < 0
      ? `${money(-sum.hybrid_savings_usd)} extra cost` : `${money(sum.hybrid_savings_usd)} saved`) : unavailable;
    $("hybridSavingsPercent").textContent = !comparable ? "Percentage unavailable" : sum.hybrid_savings_percent == null
      ? "Percentage undefined: oracle-only estimate is $0" : sum.hybrid_savings_percent < 0
      ? `${Math.abs(sum.hybrid_savings_percent).toFixed(1)}% higher cost` : `${sum.hybrid_savings_percent.toFixed(1)}% estimated savings`;
    for (const [role, prefix] of [["oracle", "oracle"], ["proxy", "local"]]) {
      const calls = sum[prefix + "_model_calls"] || 0;
      const input = sum[prefix + "_input_tokens"] || 0;
      const cached = sum[prefix + "_cached_input_tokens"] || 0;
      const writes = sum[prefix + "_cache_write_tokens"] || 0;
      const cost = sum[prefix + "_estimated_usd"];
      const basis = sum[prefix + "_cost_basis"] === "current_configured_prices" ? " at current configured prices" : "";
      $(role + "ApiCost").textContent = !calls ? "No calls yet" : cost == null ? "Set prices for this session's model and all used token types; usage must be recorded" : `$${cost.toFixed(6)} estimated${basis}`;
      $(role + "CacheUsage").textContent = !calls ? "No API usage recorded." : `${input.toLocaleString()} input / ${cached.toLocaleString()} cached (${input ? (100 * cached / input).toFixed(1) : "0"}%) / ${writes.toLocaleString()} cache writes`;
    }
  }

  function renderModel(model) {
    lastModel = model;
    const running = !!model.listening;
    $("temperature").disabled = $("proxyProvider").value === "openai";
    $("enableThinking").disabled = ["openai", "zai"].includes($("proxyProvider").value);
    $("maxInput").max = $("proxyProvider").value === "zai" ? "900000" : "131072";
    $("maxOutput").max = $("proxyProvider").value === "zai" ? "131072" : "32768";
    const nimProxy = $("proxyProvider").value !== "unsloth";
    document.querySelectorAll(".openai-proxy").forEach(x => x.classList.toggle("hidden", $("proxyProvider").value !== "openai"));
    document.querySelectorAll(".openai-oracle").forEach(x => x.classList.toggle("hidden", $("oracleProvider").value !== "openai"));
    for (const role of ["proxy", "oracle"]) {
      const provider = $(role + "Provider").value;
      document.querySelectorAll(".zai-" + role).forEach(x => x.classList.toggle("hidden", provider !== "zai"));
      document.querySelectorAll(".pricing-" + role).forEach(x => x.classList.toggle("hidden", !["openai", "zai"].includes(provider)));
    }
    document.querySelectorAll(".adaptive-oracle").forEach(x => x.classList.toggle("hidden", !["zai", "openai"].includes($("oracleProvider").value)));
    $("oracleReasoning").disabled = $("oracleAdaptive").checked && ["zai", "openai"].includes($("oracleProvider").value);
    $("unslothSettings").classList.toggle("hidden", nimProxy);
    $("unslothLog").classList.toggle("hidden", nimProxy);
    $("proxyNimModel").disabled = !nimProxy;
    $("modelHealth").className = "status-pill" + (running ? "" : " muted");
    $("modelHealth").textContent = running ? "Listening" : "Offline";
    $("connectionDot").classList.add("online");
    $("connectionTitle").textContent = "Command center online";
    $("connectionDetail").textContent = "Selections for new sessions";
    renderSelections();
    const logs = model.logs || [];
    if (logs.length) {
      const node = $("modelLog");
      if (modelCursor === 0) node.textContent = "";
      for (const item of logs) {
        node.textContent += item.line;
        modelCursor = Math.max(modelCursor, item.id);
      }
      if (node.textContent.length > 50000) node.textContent = node.textContent.slice(-40000);
      node.scrollTop = node.scrollHeight;
    }
  }

  function fillConfig(cfg) {
    if (configLoaded) return;
    const studio = cfg.studio || {};
    const local = cfg.local || {};
    const port = new URL(local.base_url || "http://127.0.0.1:8888/v1").port || "8888";
    const values = {
      studioModel: studio.model || (local.provider && local.provider !== "unsloth" ? "" : local.model) || "", studioPort: studio.port || port,
      studioContext: studio.context || "32768", cacheK: studio.cache_k || "bf16",
      cacheV: studio.cache_v || "bf16", studioParallel: studio.parallel || "1",
      maxInput: local.max_input_tokens || "24000", maxOutput: local.max_tokens || "1024",
      temperature: local.temperature ?? "0.7", proxyTopP: local.top_p ?? "0.95",
      commandChecks: local.command_checks || (local.provider === "zai" ? "essential" : "strict"), targetInput: cfg.target || "",
      runtimeSelect: cfg.runtime || "docker", wslDistro: cfg.wsl_distro || "kali-linux",
      wslUser: cfg.wsl_user || "kali", networkInput: cfg.network || "",
      networkPolicy: cfg.network_policy || "internal_lab",
      scanPorts: cfg.scan_ports || "", configObjective: cfg.objective || "",
      containerMemory: cfg.container_memory || "512m", containerCpus: cfg.container_cpus || "1",
      maxSteps: cfg.max_steps || "20", commandTimeout: cfg.command_timeout_seconds || "45",
      objectiveInput: cfg.objective || ""
    };
    for (const [id, value] of Object.entries(values)) $(id).value = value;
    $("whippetEnabled").checked = cfg.whippet_enabled !== false;
    let preferences = cfg.ui;
    try { preferences = JSON.parse(localStorage.getItem("harpUiSettings") || "null") || preferences; } catch {}
    if (preferences) applyInterfaceSettings(preferences);
    renderRuntimeFields();
    $("enableThinking").checked = !!local.enable_thinking;
    $("proxyProvider").value = local.provider || "unsloth";
    setModelOptions("proxyNimModel", [], local.provider !== "unsloth" ? local.model || "" : "");
    $("proxyOpenaiUrl").value = local.provider === "openai" ? local.base_url || "https://api.openai.com/v1" : "https://api.openai.com/v1";
    $("proxyAccess").value = local.access_program || "daybreak_blue";
    const oracle = cfg.oracle || {};
    $("oracleProvider").value = oracle.provider || "codex";
    $("oracleReasoning").value = oracle.reasoning_effort || "low";
    $("oracleAdaptive").checked = oracle.adaptive_reasoning === true;
    $("oracleSearch").checked = oracle.web_search_enabled === true;
    $("oracleTemperature").value = oracle.temperature ?? 1;
    $("oracleTopP").value = oracle.top_p ?? 0.95;
    $("oracleReply").value = oracle.max_tokens || 16384;
    $("oracleEvidence").value = oracle.evidence_depth || "compact";
    $("proxyReasoning").value = local.reasoning_effort || "low";
    setModelOptions("oracleModel", [], oracle.model || "");
    $("oracleOpenaiUrl").value = oracle.base_url || "https://api.openai.com/v1";
    $("oracleAccess").value = oracle.access_program || "daybreak_blue";
    $("oracleCycles").value = oracle.max_cycles || 12;
    $("oracleSteps").value = oracle.steps_per_cycle || 6;
    $("oracleUnlimited").checked = oracle.unlimited_budget === true;
    for (const [role, model] of [["proxy", local], ["oracle", oracle]]) {
      $(role + "CacheTtl").value = model.prompt_cache_ttl || "30m";
      for (const [suffix, field] of [["InputPrice", "input_usd_per_million"], ["CachedPrice", "cached_input_usd_per_million"], ["WritePrice", "cache_write_usd_per_million"], ["OutputPrice", "output_usd_per_million"]])
        $(role + suffix).value = model[field] ?? "";
    }
    configLoaded = true;
  }

  function cacheConfig(role) {
    const settings = {prompt_cache_ttl: $(role + "CacheTtl").value};
    for (const [suffix, field] of [["InputPrice", "input_usd_per_million"], ["CachedPrice", "cached_input_usd_per_million"], ["WritePrice", "cache_write_usd_per_million"], ["OutputPrice", "output_usd_per_million"]]) {
      const value = $(role + suffix).value.trim();
      settings[field] = value === "" ? null : Number(value);
    }
    return settings;
  }

  function renderRuntimeFields() {
    const runtime = $("runtimeSelect").value;
    document.querySelectorAll("[data-runtime]").forEach(field => { field.hidden = field.dataset.runtime !== runtime; });
    $("networkPolicy").disabled = runtime !== "docker";
  }

  function configPayload() {
    return {
      studio: {model: $("studioModel").value.trim(), port: Number($("studioPort").value),
               context: Number($("studioContext").value), cache_k: $("cacheK").value,
               cache_v: $("cacheV").value, parallel: Number($("studioParallel").value)},
      local: {provider: $("proxyProvider").value, model: $("proxyNimModel").value.trim(),
              base_url: $("proxyOpenaiUrl").value.trim(), access_program: $("proxyAccess").value,
              ...(["openai", "zai"].includes($("proxyProvider").value) ? cacheConfig("proxy") : {}),
              max_input_tokens: Number($("maxInput").value), max_tokens: Number($("maxOutput").value),
              reasoning_effort: $("proxyReasoning").value,
              command_checks: $("commandChecks").value,
              ...($("proxyProvider").value === "zai" ? {top_p: Number($("proxyTopP").value)} : {}),
              temperature: Number($("temperature").value), enable_thinking: $("enableThinking").checked},
      target: $("targetInput").value.trim(), runtime: $("runtimeSelect").value,
      wsl_distro: $("wslDistro").value.trim(), wsl_user: $("wslUser").value.trim(),
      network: $("networkInput").value.trim(),
      network_policy: $("networkPolicy").value, scan_ports: $("scanPorts").value.trim(),
      objective: $("configObjective").value.trim(), container_memory: $("containerMemory").value.trim(),
      container_cpus: Number($("containerCpus").value), max_steps: Number($("maxSteps").value),
      whippet_enabled: $("whippetEnabled").checked,
      command_timeout_seconds: Number($("commandTimeout").value),
      oracle: {provider: $("oracleProvider").value, model: $("oracleModel").value.trim(),
               base_url: $("oracleOpenaiUrl").value.trim(), access_program: $("oracleAccess").value,
               ...(["openai", "zai"].includes($("oracleProvider").value) ? cacheConfig("oracle") : {}),
               reasoning_effort: $("oracleReasoning").value,
               adaptive_reasoning: ["zai", "openai"].includes($("oracleProvider").value) && $("oracleAdaptive").checked,
               web_search_enabled: $("oracleSearch").checked,
               ...($("oracleProvider").value === "zai" ? {temperature: Number($("oracleTemperature").value), top_p: Number($("oracleTopP").value)} : {}),
               max_cycles: Number($("oracleCycles").value), steps_per_cycle: Number($("oracleSteps").value),
               unlimited_budget: $("oracleUnlimited").checked,
               evidence_depth: $("oracleEvidence").value,
               max_tokens: $("oracleProvider").value === "zai" ? Number($("oracleReply").value) : $("oracleProvider").value === "openai" ? 4096 : 1024}
    };
  }

  async function saveConfig(showToast = true) {
    const result = await post("/api/config", configPayload());
    renderSelections();
    if (showToast) toast("Configuration saved for new sessions");
    return result;
  }

  function eventCategory(event) {
    const kind = event.type || "";
    if (kind.startsWith("research_") || kind.startsWith("oracle_") || kind === "invalid_oracle_reply") return "oracle";
    if (kind === "delegation") return "oracle";
    if (kind.startsWith("local_") || kind.startsWith("proxy_") || kind === "invalid_local_reply" || kind === "memory_query") return "local";
    if (kind === "terminal_output" || kind === "approved_root_terminal" || kind === "probe_outcomes") return "terminal";
    if (kind.startsWith("root_approval") || kind.startsWith("command_review")) return "approval";
    return "system";
  }

  function verboseCategory(event) {
    const kind = event.type || "";
    if (kind.startsWith("recon_") || kind === "port_discovery" || kind === "deeper_port_discovery" ||
        kind === "ad_port_check" || kind.startsWith("deterministic_") || kind === "recon_fallback") return "recon";
    return eventCategory(event);
  }

  function eventInfo(event) {
    const kind = event.type || "event";
    if (kind === "recon_started") return ["Reconnaissance started", `Kali runtime: ${event.runtime || "unknown"}`, ""];
    if (kind === "recon_command_started") return ["Recon command running", event.stage || "Reconnaissance", event.command || ""];
    if (kind === "recon_command_finished") return ["Recon command finished", `${event.stage || "Reconnaissance"} · exit ${event.exit_code} · ${event.seconds}s`, event.command || ""];
    if (kind === "recon_finished") return ["Reconnaissance complete", `${event.services ?? 0} services · ${event.seconds ?? 0}s`, ""];
    if (kind === "recon_reused") return ["Saved reconnaissance reused", `${event.services ?? 0} services · from session ${event.source_session || "unknown"}${event.match_hostname ? ` · matched ${event.match_hostname} at ${event.source_target}` : ""}`, ""];
    if (kind === "recon_identity_probe") return ["Target identity checked", event.hostnames?.length ? `Reported ${event.hostnames.join(", ")}` : "No matching HTB hostname reported", event.result?.command || ""];
    if (kind === "recon_cache_error") return ["Recon save failed", event.error || "The run can continue, but its findings were not cached", ""];
    if (kind === "recon_failed") return ["Reconnaissance failed", event.error || "Startup failed", ""];
    if (kind === "recon_cancelled") return ["Reconnaissance stopped", "Stopped after the current command", ""];
    if (kind === "oracle_research_turn") return ["Oracle research allowance", `Research turn ${event.count} / 16; execution cycles preserved`, ""];
    if (kind.startsWith("research_")) return [kind === "research_rejected" ? "Research request returned to oracle" : kind === "research_cache_hit" ? "Research cache reused" : kind === "research_started" ? "Oracle research started" : "Oracle research completed",
      `${event.operation || ""} ${event.status || ""}${event.seconds != null ? ` · ${event.seconds}s` : ""}`, event.detail || (event.result ? JSON.stringify(event.result, null, 2) : event.reason || event.source_id || event.task_id || "")];
    if (kind === "oracle_effort_selected") return ["Oracle reasoning effort", `${event.effort} / ${event.source} / cycle ${event.cycle}`, ""];
    if (kind === "proxy_effort_recommendation") return ["Proxy effort recommendation", event.effort, ""];
    if (kind === "oracle_plan") return ["Oracle plan", event.plan, ""];
    if (kind === "oracle_strategy_rejected") return ["Strategy returned to oracle", event.reason, ""];
    if (kind === "oracle_check") return ["Next discriminating check", `${event.check?.hypothesis || ""} · ${event.check?.fact || ""}`, `Positive: ${event.check?.expected_positive || ""}\nNegative: ${event.check?.expected_negative || ""}`];
    if (kind === "probe_outcomes") return ["Scoped probe results", "Each result applies only to its identity, resource and operation",
      (event.outcomes || []).map(row => `${row.principal} · ${row.host}/${row.resource} · ${row.operation}: ${row.status}\n${row.quote}`).join("\n\n")];
    if (kind === "delegation") return ["Task delegated", `${event.objective} · ${event.unbridled ? "unbridled" : event.budget == null ? "no step budget" : `up to ${event.budget} steps`}`, ""];
    if (kind === "oracle_budget_changed") return ["Oracle budget changed", event.unlimited_budget ? "Oracle cycle budget removed; delegation review limits remain" : "Configured budgets restored", ""];
    if (kind === "local_action") {
      const action = event.action || {};
      const command = action.command || action.finding || action.memory_query || "";
      const artifact = action.artifact ? `\nArtifact: ${action.artifact.title} — ${action.artifact.value}` : "";
      return [`Proxy model · step ${event.step}`, action.thought || "Action selected", command + artifact];
    }
    if (kind === "terminal_output") return ["Terminal output", event.command || "", event.text || ""];
    if (kind === "local_terminal" || kind === "oracle_terminal" || kind === "approved_root_terminal") {
      const result = event.result || {};
      return [kind === "local_terminal" ? "Proxy command" : kind === "oracle_terminal" ? "Oracle command" : "Approved root command",
              `Exit ${result.exit_code} · ${result.seconds || 0}s · ${result.command || ""}`, result.output || "(no output)"];
    }
    if (kind === "port_discovery") return ["Port sweep complete", `${(event.findings || []).length} open TCP ports · exit ${event.result?.exit_code}`, event.result?.command || ""];
    if (kind === "deeper_port_discovery") return ["Slower port sweep", `${(event.findings || []).length} open TCP ports found`, event.result?.command || ""];
    if (kind === "ad_port_check") return ["AD port check", `${(event.findings || []).length} open TCP ports confirmed`, event.result?.command || ""];
    if (kind === "deterministic_recon") return ["Version detection complete", `${(event.findings || []).length} open services identified`, event.result?.command || ""];
    if (kind === "deterministic_http_probe") return ["HTTP probe", `Port ${event.probe?.port} · status ${event.probe?.status || "unknown"}`, event.probe?.body_excerpt || ""];
    if (kind === "deterministic_smb_probe") return ["SMB probe", `${event.probe?.option || ""} · exit ${event.probe?.exit_code}`, event.probe?.output_excerpt || ""];
    if (kind === "deterministic_recon_retry") return ["Version scan retry", `${(event.findings || []).length} open services identified`, event.result?.command || ""];
    if (kind === "recon_fallback") return ["Port sweep retained", "Version scan was filtered; using the open ports from the initial sweep", ""];
    if (kind === "oracle_nim_error") return ["Oracle run error", event.error || "The model request failed", ""];
    if (kind === "oracle_transport_retry") return ["Oracle connection retry", `Retry ${event.attempt}/2 after ${(event.reason || "transport interruption").replaceAll("_", " ")}; continuing automatically`, "No action was accepted. Token usage for the interrupted request is unknown."];
    if (kind === "oracle_nim_stopped") return ["Oracle stopped", `Reason: ${(event.reason || "unknown").replaceAll("_", " ")}`, event.detail || ""];
    if (kind === "oracle_nim_usage") return ["Oracle response", `${event.input_tokens ?? "?"} input / ${event.output_tokens ?? "?"} output tokens / ${event.cached_input_tokens ?? 0} cached / ${event.cache_write_tokens ?? 0} cache writes / ${event.seconds ?? "?"}s`, event.cost_basis ? (event.estimated_usd == null ? "Cost unknown: configure token prices" : `Estimated $${event.estimated_usd.toFixed(6)} before account allowances`) : ""];
    if (kind === "oracle_nim_request") return ["Oracle planning", `Request sent to ${event.model} · cycle ${event.cycle}`, ""];
    if (kind === "oracle_nim_recovery") return ["Oracle reviewing failure", `Worker stopped: ${(event.reason || "unknown").replaceAll("_", " ")} · correction ${event.attempt}`, ""];
    if (kind === "oracle_nim_probe") return ["Oracle probe", "One scoped, read-only command", event.command || ""];
    if (kind === "oracle_nim_resumed") return ["Oracle resumed", "Continuing this session's plan and cycle budget", ""];
    if (kind === "oracle_nim_probe_rejected") return ["Oracle probe needs correction", event.reason || "Probe check failed", `Correction ${event.attempt}`];
    if (kind === "local_command_rejected") return ["Command check rejected", event.reason || "Invalid command", event.command || ""];
    if (kind === "command_review_requested") return ["Command awaiting review", event.reason || "Check flagged command", event.command || ""];
    if (kind === "command_review_decided") return [event.approved ? "Command accepted" : event.approved === false ? "Command denied" : "Review stopped", `Review wait ${event.wait_seconds ?? 0}s · ${event.reason || ""}`, event.command || ""];
    if (kind === "local_command_check") return ["Shell syntax checked", `Exit ${event.result?.exit_code ?? "?"}`, event.result?.exit_code ? event.result?.output || "" : ""];
    if (kind === "local_response_mode_changed") return ["Proxy reply retry", "Retrying a malformed reply with stricter settings", ""];
    if (kind === "delegation_stopped") return event.reason === "null_auth_denied"
      ? ["Legacy anonymous-access stop", "The older rule did not distinguish authentication, resource permissions and tool errors. Review the scoped evidence.", ""]
      : ["Delegation stopped", `Reason: ${(event.reason || "unknown").replaceAll("_", " ")}`, ""];
    if (kind === "artifact_recorded") return [kind === "artifact_recorded" && event.kind === "flag" ? "Flag captured" : "Artifact recorded", `${event.title} · ${event.kind}`, ""];
    if (kind === "verified_success") return ["Success verified", event.evidence || "", ""];
    if (kind === "finish") return ["Session finished", `Outcome: ${event.success}`, ""];
    if (kind.startsWith("root_approval")) return [kind.replaceAll("_", " "), event.source || "Exact root command", event.command || ""];
    if (kind === "context_compaction") return ["Context compacted", `Prompt ${event.prompt_tokens} / ${event.budget_tokens} tokens`, ""];
    if (kind === "operator_stop_requested") return ["Stop requested", "Worker will stop after its current step", ""];
    return [kind.replaceAll("_", " "), "", ""];
  }

  function verboseRow(event) {
    const [title, description] = eventInfo(event);
    const row = el("details", `verbose-entry ${verboseCategory(event)}`);
    const summary = el("summary", "verbose-entry-summary");
    summary.append(el("time", "", event.at ? new Date(event.at).toLocaleTimeString() : ""),
                   el("strong", "", title), el("span", "", description || ""));
    row.append(summary);
    const command = event.result?.command || event.command || event.action?.command || "";
    const output = event.result?.output || event.probe?.output_excerpt || event.text || "";
    if (command) row.append(el("pre", "verbose-command", command));
    if (output) row.append(el("pre", "verbose-output", output));
    const raw = el("details", "verbose-raw");
    raw.append(el("summary", "", "Event fields"), el("pre", "", JSON.stringify(event, null, 2)));
    row.append(raw);
    return row;
  }

  function renderVerbose() {
    const feed = $("verboseFeed");
    feed.replaceChildren();
    const filter = $("verboseFilter").value;
    const visible = verboseEvents.filter(event => filter === "all" || verboseCategory(event) === filter);
    if (!visible.length) feed.append(el("p", "muted-text", selected ? "No matching events yet." : "No session events yet."));
    else for (const event of visible) feed.append(verboseRow(event));
    if ($("verboseFollow").checked) feed.scrollTop = feed.scrollHeight;
  }

  function appendVerbose(events) {
    if (!events.length) return;
    verboseEvents.push(...events);
    if (currentPage !== "verbose") return;
    const feed = $("verboseFeed");
    if (feed.children.length === 1 && feed.firstElementChild?.tagName === "P") feed.replaceChildren();
    const filter = $("verboseFilter").value;
    for (const event of events) if (filter === "all" || verboseCategory(event) === filter) feed.append(verboseRow(event));
    if ($("verboseFollow").checked) feed.scrollTop = feed.scrollHeight;
  }

  function appendEvents(events) {
    appendVerbose(events);
    const feed = $("activityFeed");
    if (events.length && feed.querySelector(".empty-state")) feed.replaceChildren();
    const nearBottom = feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 80;
    for (const event of events) {
      if (event.type === "terminal_output") continue;
      if (event.type === "local_command_check" && event.result?.exit_code === 0) continue;
      const category = eventCategory(event);
      const [title, description, command] = eventInfo(event);
      const row = el("div", `event ${category}`);
      row.dataset.category = category;
      row.hidden = currentFilter !== "all" && currentFilter !== category;
      const icon = ({oracle: "✦", local: "◈", terminal: ">", approval: "!", system: "·"})[category];
      row.append(el("div", "event-icon", icon));
      const body = el("div", "event-body");
      const top = el("div", "event-top");
      top.append(el("strong", "event-title", title), el("time", "event-time", event.at ? new Date(event.at).toLocaleTimeString() : ""));
      body.append(top);
      if (description) body.append(el("p", "event-description", description));
      if (command) body.append(el("code", "event-command", command));
      row.append(body);
      feed.append(row);
    }
    while (feed.children.length > 350) feed.firstChild.remove();
    if (nearBottom) feed.scrollTop = feed.scrollHeight;
  }

  function renderSummary() {
    if (!selected) {
      $("sessionHeading").textContent = startPending ? "Preparing new session" : "No session selected";
      $("sessionState").textContent = startPending ? "STARTING" : "IDLE";
      $("sessionState").className = "status-pill muted";
      $("metricTools").textContent = "0";
      $("metricModel").textContent = "0";
      $("metricTokens").textContent = "0";
      $("metricFlags").textContent = "0 / 2";
      renderCostSummary();
      $("metricOutcome").textContent = startPending ? "Starting" : "—";
      $("metricOutcomeNote").textContent = startPending ? "Preparing reconnaissance" : "Awaiting evidence";
      $("reconProgress").classList.toggle("hidden", !startPending);
      $("reconProgressTitle").textContent = "Preparing new session";
      $("reconStage").textContent = "Creating the Kali workspace and starting reconnaissance.";
      $("reconCurrentCommand").textContent = "Waiting for the first command";
      $("verboseSession").textContent = startPending ? "Preparing new session" : "No session selected";
      $("verboseStage").textContent = startPending ? "Starting reconnaissance" : "Start a session to see live details.";
      for (const id of ["delegateButton", "stopLocal", "runManual", "markSuccess", "finishSession", "resumeOracle"]) $(id).disabled = true;
      $("resumeOracle").classList.add("hidden");
      $("unlimitedBudgetRow").classList.add("hidden");
      $("researchStatus").textContent = "Research: no session selected.";
      $("capabilityFacts").replaceChildren();
      renderElapsed();
      return;
    }
    const sum = selected.summary;
    $("sessionHeading").textContent = `${sum.target} · ${sum.mode}`;
    $("sessionState").className = "status-pill" + (["active", "recon"].includes(sum.status) ? "" : " muted");
    $("sessionState").textContent = replay ? "RECORDED REPLAY" :
      sum.termination_reason === "host_interrupted" ? "INTERRUPTED" : sum.status.toUpperCase();
    $("metricTools").textContent = sum.terminal_tool_calls ?? "0";
    $("metricModel").textContent = sum.local_model_calls ?? "0";
    $("metricTokens").textContent = ((sum.local_input_tokens || 0) + (sum.local_output_tokens || 0)).toLocaleString();
    renderCostSummary(sum);
    const researchLabels = {disabled: "Disabled for this session", enabled_unused: "Enabled · no requests yet",
      requested: "Request in progress", completed: "Last request completed", failed: "Last request failed",
      interrupted: "Request interrupted"};
    const researchUsage = sum.research_usage;
    $("researchStatus").textContent = `Research: ${researchLabels[sum.research_status] || "Status unavailable"}${researchUsage ? ` · ${researchUsage.search_requests} searches · ${researchUsage.source_requests} source reads · ${researchUsage.failed_requests} failures` : ""}`;
    const flagCount = Object.values(selected.flags || {}).filter(x => x.found).length;
    const evidence = sum.capability_evidence || {};
    const facts = $("capabilityFacts");
    facts.replaceChildren();
    for (const row of (evidence.facts || [])) {
      const item = el("p", "capability-fact");
      item.textContent = `${row.principal} · ${row.host}/${row.resource} · ${row.operation}: ${row.status} (${row.source === "recon" ? `recon ${row.recon}` : `observation ${row.observation}`})`;
      facts.append(item);
    }
    for (const row of (evidence.prerequisites || [])) {
      const item = el("p", "capability-fact");
      item.textContent = `${row.fact} · ${row.resource}: ${row.state.replaceAll("_", " ")}`;
      facts.append(item);
    }
    if (!facts.children.length) facts.textContent = "No scoped observations yet.";
    $("metricFlags").textContent = `${flagCount} / 2`;
    $("metricOutcome").textContent = sum.status === "recon" ? "Scanning" : sum.success === "yes" ? (flagCount === 2 ? "Success" : "Other result") : sum.termination_reason === "host_interrupted" ? "Interrupted" : sum.success === "no" ? "No" : "Pending";
    $("metricOutcomeNote").textContent = sum.status === "recon" ? "Reconnaissance in progress" : sum.termination_reason === "host_interrupted" && sum.success !== "yes" ? (sum.cleanup_error ? "Recovery needs runtime cleanup" : "Recovered after host interruption") : sum.success === "yes" && flagCount < 2 ? "No flag pair recorded" : sum.time_to_success_seconds != null ? `In ${formatDuration(sum.time_to_success_active_seconds ?? sum.time_to_success_seconds)} active time` : sum.human_intervention_at ? "Human tactical help recorded" : "Before human tactical help";
    const live = document.querySelector(".live-indicator");
    live.classList.toggle("muted", !!replay || !["active", "recon"].includes(sum.status));
    const activityStatus = replay ? "RECORDED REPLAY" : ["active", "recon"].includes(sum.status) ? "LIVE" : "SAVED SESSION";
    if ($("activityStatusText").textContent !== activityStatus) $("activityStatusText").textContent = activityStatus;
    $("reconProgress").classList.toggle("hidden", sum.status !== "recon");
    $("reconProgressTitle").textContent = sum.recon_stage || "Reconnaissance";
    $("reconStage").textContent = sum.recon_command ? "Running now" : "Preparing the next command";
    $("reconCurrentCommand").textContent = sum.recon_command || "Waiting for the next command";
    $("verboseSession").textContent = `${sum.target} · ${sum.mode}`;
    $("verboseStage").textContent = sum.status === "recon" ? `Reconnaissance: ${sum.recon_stage || "Preparing Kali"}` : `Session ${sum.status}`;
    const active = !replay && sum.status === "active";
    for (const id of ["delegateButton", "stopLocal", "runManual", "markSuccess", "finishSession"]) $(id).disabled = !active;
    const canResumeOracle = active && ["nvidia_nim", "openai", "zai"].includes(selected.oracle_provider) && !!selected.activity.oracle_stopped;
    $("resumeOracle").classList.toggle("hidden", !canResumeOracle);
    $("resumeOracle").disabled = !canResumeOracle;
    if (document.activeElement !== $("stepsInput")) $("stepsInput").value = selected.delegation_limit || 20;
    if (sum.mode === "local-only") $("runManual").disabled = true;
    if (sum.mode === "frontier-only") $("delegateButton").disabled = true;
    $("unlimitedBudgetRow").classList.toggle("hidden", !["nvidia_nim", "openai", "zai"].includes(selected.oracle_provider));
    if (budgetSessionId !== selected.id) { $("unlimitedBudgetInput").checked = selected.oracle_unlimited_budget === true; budgetSessionId = selected.id; }
    $("oracleIdentity").textContent = selected.oracle_provider === "codex" ? "Oracle / Codex" : `Oracle / ${selected.oracle_provider} / ${selected.oracle_model}`;
    $("proxyIdentity").textContent = `Proxy / ${selected.proxy_provider} / ${selected.proxy_model}`;
    $("oraclePlan").textContent = selected.activity.oracle_plan || "The oracle will publish a plan after reviewing reconnaissance.";
    const local = selected.activity.local_action;
    $("localAction").textContent = local ? `${local.thought || "Working"}${local.command ? " · " + local.command : ""}${sum.last_delegate_stop ? " · Stopped: " + sum.last_delegate_stop.replaceAll("_", " ") : ""}` : "Awaiting a delegated objective.";
    const ports = (selected.recon || []).map(x => `${x.port}/${x.service || "unknown"}`);
    $("reconSummary").textContent = ports.length ? ports.join(" · ") : "No open services reported yet.";
    const approval = selected.pending_approval;
    $("approvalCard").classList.toggle("hidden", !approval);
    if (approval) {
      const check = approval.source === "command_check";
      $("approvalTitle").textContent = check ? "Review flagged command" : "Root authorization";
      $("approvalDescription").textContent = check
        ? `HARP flagged the proxy command: ${approval.reason} The proxy is paused until you decide.`
        : `${approval.source === "local" ? "Proxy model" : "Oracle"} requested a command requiring root privileges.`;
      $("approvalCommand").textContent = approval.command;
      if (check && reviewDialogShownId !== approval.id) {
        reviewDialogShownId = approval.id;
        openApprovalDialog(approval);
      }
    }
    if (document.activeElement !== $("objectiveInput") && !$("objectiveInput").value.trim()) $("objectiveInput").value = selected.objective || "";
    renderElapsed();
    renderFlags();
    const celebrationId = (replay ? "replay:" : "") + selected.id;
    if (sum.status === "finished" && sum.success === "yes" && flagCount === 2 && !celebratedSessions.has(celebrationId)
        && (replay || !selected.success_viewed)) {
      $("successDialog").showModal();
      celebratedSessions.add(celebrationId);
    }
    if (!replay && celebratedSessions.has(celebrationId) && !selected.success_viewed) acknowledgeSuccess(selected);
    const signature = JSON.stringify((selected.artifacts || []).map(x => [x.id, x.value]));
    if (signature !== artifactSignature) {
      artifactSignature = signature;
      renderArtifacts(true);
    }
  }

  function renderElapsed() {
    if (!selected) {
      const elapsed = startPending && startingAt ? (Date.now() - startingAt) / 1000 : 0;
      $("metricElapsed").textContent = startPending ? formatDuration(elapsed) : "—";
      $("reconClock").textContent = formatDuration(elapsed);
      $("verboseElapsed").textContent = startPending ? formatDuration(elapsed) : "—";
      return;
    }
    const live = ["active", "recon"].includes(selected.summary.status);
    const seconds = replay ? replay.seconds : live ? Date.now() / 1000 - selected.started_epoch : selected.duration_seconds;
    $("metricElapsed").textContent = formatDuration(seconds);
    $("verboseElapsed").textContent = formatDuration(seconds);
    $("reconClock").textContent = formatDuration(selected.summary.status === "recon"
      ? (replay ? replay.seconds : Date.now() / 1000 - selected.started_epoch) : selected.summary.recon_elapsed_seconds);
  }

  function renderFlags() {
    const flags = selected?.flags || {};
    const artifacts = selected?.artifacts || [];
    for (const [name, prefix] of [["user.txt", "user"], ["root.txt", "root"]]) {
      const flag = flags[name] || {found: false};
      const artifact = artifacts.find(x => x.id === flag.artifact_id);
      $(prefix + "FlagCard").classList.toggle("found", !!flag.found);
      $(prefix + "FlagStatus").textContent = flag.found ? "CAPTURED" : "NOT FOUND";
      $(prefix + "FlagValue").textContent = artifact?.value || "Awaiting capture";
      $(prefix + "FlagTime").textContent = flag.found ? `Captured ${formatTime(flag.at)} · ${artifact?.source || "terminal evidence"}` : "Awaiting terminal evidence";
    }
    $("unseenBanner").classList.toggle("hidden", !Object.values(flags).some(x => x.unseen));
    if (currentPage === "flags") acknowledgeFlags();
  }

  function renderArtifacts(force = false) {
    if (!force || !selected) return;
    const generation = ++artifactGeneration;
    for (const url of artifactImageUrls) URL.revokeObjectURL(url);
    artifactImageUrls.clear();
    const all = selected.artifacts || [];
    const query = $("artifactSearch").value.trim().toLowerCase();
    const kind = $("artifactFilter").value;
    const items = all.filter(x => (kind === "all" || x.kind === kind) &&
      (!query || `${x.title} ${x.kind} ${x.source} ${x.value}`.toLowerCase().includes(query)));
    $("artifactCount").textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
    const grid = $("artifactGrid");
    grid.replaceChildren();
    if (!items.length) {
      const empty = el("div", "empty-state");
      empty.append(el("div", "empty-icon", "▣"), el("strong", "", all.length ? "No matching artifacts" : "No artifacts yet"),
                   el("p", "", all.length ? "Try a different search or filter." : "Evidence-backed findings will appear here."));
      grid.append(empty);
      return;
    }
    for (const item of [...items].reverse()) {
      const card = el("article", "artifact-card");
      const top = el("div", "artifact-card-top");
      top.append(el("span", `artifact-kind ${item.kind}`, item.kind), el("time", "event-time", formatTime(item.at)));
      card.append(top, el("h3", "", item.title),
                  el("p", "", item.evidence_backed ? "Recorded from terminal evidence" : "Operator note"));
      const value = el("div", "artifact-value");
      value.append(el("code", "", item.value));
      card.append(value);
      const source = el("div", "artifact-source");
      source.append(el("strong", "", "SOURCE  "), document.createTextNode(item.source || "—"));
      card.append(source);
      if (item.attachment) {
        if (["image/png", "image/jpeg"].includes(item.attachment.media_type)) {
          const preview = el("div", "artifact-image-wrap");
          preview.append(el("p", "muted-text", "Loading image…"));
          card.append(preview);
          loadArtifactImage(item, selectedId, preview, generation);
        }
        const download = el("button", "button secondary artifact-download", `↓ Download ${item.attachment.filename}`);
        download.addEventListener("click", () => downloadAttachment(item));
        card.append(download);
      }
      grid.append(card);
    }
  }

  async function loadArtifactImage(item, sessionId, preview, generation) {
    try {
      const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/attachments/${item.id}?preview=1`,
        {cache: "no-store", headers: {"X-HARP-Token": token}});
      if (!response.ok) throw new Error("Image preview unavailable. Download the preserved file to inspect it in Kali.");
      const blob = await response.blob();
      if (generation !== artifactGeneration) return;
      if (!["image/png", "image/jpeg"].includes(blob.type)) throw new Error("Unsupported image preview.");
      const url = URL.createObjectURL(blob);
      artifactImageUrls.add(url);
      const image = el("img", "artifact-image");
      image.alt = item.title;
      image.addEventListener("error", () => {
        preview.replaceChildren(el("p", "muted-text", "Image could not be rendered. Original download is available."));
        URL.revokeObjectURL(url); artifactImageUrls.delete(url);
      });
      image.src = url;
      const fullSize = el("a", "artifact-image-link", "Open full-size image");
      fullSize.href = url; fullSize.target = "_blank"; fullSize.rel = "noopener noreferrer";
      preview.replaceChildren(image, fullSize);
    } catch (error) {
      if (generation === artifactGeneration) preview.replaceChildren(el("p", "muted-text", error.message));
    }
  }

  async function downloadAttachment(item) {
    try {
      const response = await fetch(`/api/sessions/${encodeURIComponent(selectedId)}/attachments/${item.id}`,
        {cache: "no-store", headers: {"X-HARP-Token": token}});
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Download failed");
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = item.attachment.filename;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch (error) { toast(error.message, true); }
  }

  async function acknowledgeFlags() {
    if (replay || seenPending || !selectedId || !selected || !Object.values(selected.flags || {}).some(x => x.unseen)) return;
    seenPending = true;
    try {
      const ids = Object.values(selected.flags || {}).filter(x => x.found).map(x => x.artifact_id);
      await post(`/api/sessions/${encodeURIComponent(selectedId)}/flags-seen`, {ids});
      for (const flag of Object.values(selected.flags || {})) flag.unseen = false;
      renderFlags();
      updateBadges();
    } catch (error) { toast(error.message, true); }
    finally { seenPending = false; }
  }

  function updateBadges() {
    const unseen = sessions.reduce((sum, x) => sum + (x.unseen_flags || 0), 0);
    const flagBadge = $("flagNavBadge");
    flagBadge.textContent = String(unseen);
    flagBadge.classList.toggle("hidden", !unseen);
    flagBadge.classList.toggle("unseen", !!unseen);
    const count = selected?.artifacts?.length || 0;
    $("artifactNavCount").textContent = count;
    $("artifactNavCount").classList.toggle("hidden", !count);
  }

  async function poll() {
    if (pollBusy || replay) return;
    pollBusy = true;
    const controller = new AbortController();
    pollController = controller;
    try {
      const query = new URLSearchParams({session: selectedId, cursor: String(cursor), model_cursor: String(modelCursor)});
      const data = await api(`/api/state?${query}`, {signal: controller.signal});
      if (replay || pollController !== controller || controller.signal.aborted) return;
      sessions = data.sessions || [];
      if (data.version) $("appVersion").textContent = `v${data.version}`;
      renderDependencies(data.dependencies);
      if (startPending) {
        const reconSession = sessions.find(x => x.status === "recon");
        if (reconSession && reconSession.id !== selectedId) switchSession(reconSession.id);
      }
      if (pollController !== controller) return;
      if (selectedId && !sessions.some(x => x.id === selectedId)) {
        selectedId = "";
        cursor = 0;
        selected = null;
        $("activityFeed").replaceChildren();
      }
      if (!selectedId && sessions.length && !startPending) {
        selectedId = sessions[0].id;
        localStorage.setItem("harpSelectedSession", selectedId);
        cursor = 0;
      }
      if (!selectedId && !sessions.length) renderSummary();
      fillConfig(data.config);
      for (const [prefix, provider] of [["zai", "zai"], ["openai", "openai"], ["nim", "nvidia_nim"], ["unsloth", "unsloth"]]) {
        const status = data.keys?.[provider];
        $(prefix + "KeyStatus").textContent = status?.environment ? "Environment key active" : status?.saved ? "API key saved" : "No key imported";
        $(prefix + "KeyStatus").className = "key-status " + (status?.environment ? "environment" : status?.saved ? "saved" : "missing");
      }
      renderModel(data.model);
      if (data.selected && data.selected.id === selectedId) {
        selected = data.selected;
        cursor = selected.event_cursor;
        appendEvents(selected.events || []);
        renderSummary();
        cacheCompletedSession();
      }
      renderSessions();
      renderStartStop();
      updateBadges();
      if (!data.selected && selectedId) setTimeout(poll, 50);
      void prefetchRecentSessions();
    } catch (error) {
      if (controller.signal.aborted || pollController !== controller) return;
      if (error.message === "Session not found" || error.message === "Invalid session ID") {
        selectedId = "";
        localStorage.removeItem("harpSelectedSession");
        cursor = 0;
      }
      $("connectionTitle").textContent = "Connection unavailable";
      $("connectionDetail").textContent = error.message;
      $("connectionDot").classList.remove("online");
      if (!token) toast(error.message, true);
    } finally {
      if (pollController === controller) { pollBusy = false; pollController = null; }
    }
  }

  async function startReplay() {
    if (!selected || selected.summary.status !== "finished" || replay) return;
    const playback = {id: selectedId, loading: true, playing: false, seconds: 0, index: -1};
    replay = playback;
    renderStartStop();
    renderReplayOrbits(0);
    try {
      const data = await api(`/api/sessions/${encodeURIComponent(selectedId)}/replay`);
      if (replay !== playback) return;
      Object.assign(playback, data, {loading: false, playing: true, lastTick: performance.now()});
      celebratedSessions.delete("replay:" + selectedId);
      $("rootDialog").close();
      $("successDialog").close();
      $("replayControls").classList.remove("hidden");
      $("replaySeek").max = data.duration_seconds;
      showPage("overview");
      renderReplay(true);
    } catch (error) {
      if (replay === playback) exitReplay();
      toast(error.message, true);
    }
  }

  function exitReplay(refresh = true) {
    replay = null;
    syncReplayOrbitMotion();
    selected = null;
    cursor = 0;
    artifactSignature = "";
    verboseEvents = [];
    $("activityFeed").replaceChildren();
    $("verboseFeed").replaceChildren();
    $("successDialog").close();
    $("replayControls").classList.add("hidden");
    if (refresh) poll();
  }

  function renderReplay(force = false) {
    if (!replay || replay.loading) return;
    renderReplayOrbits(replay.seconds);
    syncReplayOrbitMotion();
    const frames = replay.frames;
    let index = 0;
    while (index + 1 < frames.length && frames[index + 1].seconds <= replay.seconds) index++;
    if (force || index !== replay.index) {
      replay.index = index;
      const frame = frames[index];
      selected = {...replay.session, ...frame, duration_seconds: replay.seconds, pending_approval: null};
      // Rebuild from the prefix so rewinding removes future findings and terminal output.
      verboseEvents = [];
      $("activityFeed").replaceChildren();
      $("verboseFeed").replaceChildren();
      appendEvents(frames.slice(0, index + 1).map(x => x.event).filter(Boolean));
      renderSummary();
      updateBadges();
      renderStartStop();
    }
    renderElapsed();
    $("replaySeek").value = replay.seconds;
    $("replayClock").textContent = `${formatDuration(replay.seconds)} / ${formatDuration(replay.duration_seconds)}`;
    $("replayPlay").textContent = replay.playing ? "Pause" : "Play";
  }

  function seekReplay(seconds) {
    if (!replay || replay.loading) return;
    replay.seconds = Math.max(0, Math.min(replay.duration_seconds, seconds));
    replay.lastTick = performance.now();
    if (replay.seconds < replay.duration_seconds) {
      celebratedSessions.delete("replay:" + replay.id);
      $("successDialog").close();
    }
    if (replay.seconds >= replay.duration_seconds) replay.playing = false;
    renderReplay(true);
  }

  function tickReplay() {
    if (!replay || replay.loading || !replay.playing) return;
    const now = performance.now();
    const delta = Math.min((now - replay.lastTick) / 1000, 1);
    replay.lastTick = now;
    replay.seconds += delta * Number($("replaySpeed").value || 1);
    const next = replay.frames[replay.index + 1];
    // Keep the startup burst visible before shortening long gaps in the evidence log.
    if ($("replaySkipIdle").checked && replay.seconds >= 4.25 && next &&
        next.seconds - replay.seconds > 3) replay.seconds = next.seconds - 3;
    if (replay.seconds >= replay.duration_seconds) {
      replay.seconds = replay.duration_seconds;
      replay.playing = false;
    }
    renderReplay();
  }

  $("replayStart").addEventListener("click", startReplay);
  $("replayExit").addEventListener("click", () => exitReplay());
  $("replayRestart").addEventListener("click", () => { if (replay) replay.playing = false; seekReplay(0); });
  $("replaySeek").addEventListener("input", () => seekReplay(Number($("replaySeek").value)));
  $("replayPlay").addEventListener("click", () => {
    if (!replay || replay.loading) return;
    if (replay.seconds >= replay.duration_seconds) seekReplay(0);
    replay.playing = !replay.playing;
    replay.lastTick = performance.now();
    renderReplay();
  });
  $("replayNext").addEventListener("click", () => {
    if (!replay || replay.loading) return;
    const finding = replay.frames.find(x => x.seconds > replay.seconds &&
      (x.event?.type === "oracle_plan" || x.event?.type === "artifact_recorded" ||
       x.event?.type === "finish" || Object.values(x.flags).filter(f => f.found).length >
       Object.values(selected.flags || {}).filter(f => f.found).length));
    seekReplay(finding?.seconds ?? replay.duration_seconds);
  });
  setInterval(tickReplay, 100);

  async function watchJob(id) {
    if (!id) { await poll(); return; }
    const timer = setInterval(async () => {
      try {
        const {job} = await api(`/api/jobs/${id}`);
        if (job.status === "running") return;
        clearInterval(timer);
        if (job.name === "start session") { startPending = false; startingAt = null; }
        if (job.status === "error") {
          if (job.name === "start session" && /stopped by operator/i.test(job.detail || "")) toast("Session stopped during reconnaissance");
          else toast(`${job.name}: ${job.detail}`, true);
        }
        else {
          toast(`${job.name}: ${job.detail || "done"}`);
          if (job.name === "start session" && job.detail) switchSession(job.detail);
        }
        poll();
      } catch (error) { clearInterval(timer); toast(error.message, true); }
    }, 850);
  }

  async function action(path, body = {}) {
    try {
      const result = await post(path, body);
      if (result.job) { toast("Operation started; live activity will update here"); watchJob(result.job); }
      else { toast(result.message || "Done"); poll(); }
      return result;
    } catch (error) { toast(error.message, true); return null; }
  }

  async function saveSessionArchive() {
    if (archiveBusy || !selectedId || selected?.summary.status !== "finished") return;
    archiveBusy = true;
    renderStartStop();
    try {
      const response = await fetch(`/api/sessions/${encodeURIComponent(selectedId)}/archive`,
        {cache: "no-store", headers: {"X-HARP-Token": token}});
      if (!response.ok) throw new Error((await response.json()).error || "Session export failed");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `harp-session-${selectedId}.zip`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
      toast("Session ZIP downloaded. It contains the session's private evidence.");
    } catch (error) { toast(error.message, true); }
    finally { archiveBusy = false; renderStartStop(); }
  }

  async function importSessionArchive(file) {
    if (archiveBusy || !file) return;
    archiveBusy = true;
    renderStartStop();
    try {
      if (file.size > 512 * 1024 * 1024) throw new Error("Session ZIP exceeds 512 MiB");
      const response = await fetch("/api/sessions/import", {method: "POST", cache: "no-store",
        headers: {"X-HARP-Token": token, "Content-Type": "application/zip"}, body: file});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Session import failed");
      toast("Session imported. Its evidence is available as a saved replay.");
      switchSession(result.session);
    } catch (error) { toast(error.message, true); }
    finally { archiveBusy = false; $("sessionArchiveFile").value = ""; renderStartStop(); }
  }

  function sessionAction(name, body = {}) {
    if (!selectedId) { toast("Select or start a session first", true); return; }
    return action(`/api/sessions/${encodeURIComponent(selectedId)}/${name}`, body);
  }

  document.querySelectorAll(".nav-item").forEach(item => item.addEventListener("click", () => showPage(item.dataset.page)));
  $("openVerbose").addEventListener("click", () => showPage("verbose"));
  $("verboseFilter").addEventListener("change", renderVerbose);
  $("verboseFollow").addEventListener("change", () => { if ($("verboseFollow").checked) $("verboseFeed").scrollTop = $("verboseFeed").scrollHeight; });
  $("themeToggle").addEventListener("click", () => {
    const next = themes[(themes.indexOf(document.documentElement.dataset.theme) + 1) % themes.length];
    applyTheme(next);
    localStorage.setItem("harpTheme", next);
    rememberInterfaceSettings();
  });
  $("animationMode").addEventListener("change", () => {
    animationMode = $("animationMode").value;
    syncAnimations();
    rememberInterfaceSettings();
  });
  $("saveSession").addEventListener("click", saveSessionArchive);
  $("importSession").addEventListener("click", () => $("sessionArchiveFile").click());
  $("sessionArchiveFile").addEventListener("change", () => importSessionArchive($("sessionArchiveFile").files[0]));
  $("refreshSessions").addEventListener("click", poll);
  for (const id of ["modeSelect", "replaySpeed", "replaySkipIdle", "freshRecon", "apiKeyProvider"]) $(id).addEventListener("change", rememberInterfaceSettings);
  $("snapshotExport").addEventListener("click", exportSettings);
  $("snapshotFile").addEventListener("change", () => previewSettingsFile($("snapshotFile").files?.[0]));
  $("snapshotApply").addEventListener("click", restoreSettings);
  $("snapshotCancel").addEventListener("click", clearSnapshotPreview);
  $("snapshotRecovery").addEventListener("click", async () => {
    try {
      const result = await post("/api/settings/recovery", {id: snapshotRecoveryId});
      downloadSettings(result.snapshot, "harp-settings-before-restore");
    } catch (error) { $("snapshotStatus").textContent = error.message; }
  });
  document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
    currentFilter = button.dataset.filter;
    document.querySelectorAll(".filter").forEach(x => x.classList.toggle("active", x === button));
    document.querySelectorAll(".event").forEach(x => { x.hidden = currentFilter !== "all" && x.dataset.category !== currentFilter; });
  }));
  $("artifactSearch").addEventListener("input", () => renderArtifacts(true));
  function celebrateWithConfetti() {
    if (!animationsEnabled()) return;
    const layer = $("successConfetti");
    const sample = el("span", "confetti-piece");
    if (typeof sample.animate !== "function") return;
    layer.replaceChildren();
    const colors = ["#22c55e", "#fbbf24", "#38bdf8", "#f472b6", "#a78bfa", "#ffffff"];
    const height = document.documentElement.clientHeight || 800;
    for (let index = 0; index < 90; index++) {
      const piece = index === 0 ? sample : el("span", "confetti-piece");
      const x = (Math.random() - .5) * 1100;
      const rise = 130 + Math.random() * 280;
      const rotation = Math.random() * 360;
      const backgroundColor = colors[index % colors.length];
      layer.append(piece);
      const animation = piece.animate([
        {transform: `translate3d(0,0,0) rotate(${rotation}deg)`, opacity: 1, backgroundColor},
        {transform: `translate3d(${x * .6}px,${-rise}px,0) rotate(${rotation + 180}deg)`, opacity: 1, backgroundColor, offset: .3},
        {transform: `translate3d(${x}px,${height * .8}px,0) rotate(${rotation + 720}deg)`, opacity: 0, backgroundColor}
      ], {duration: 1800 + Math.random() * 1200, delay: Math.random() * 180, easing: "cubic-bezier(.15,.6,.6,1)", fill: "both"});
      animation.finished.then(() => piece.remove(), () => piece.remove());
    }
  }
  $("closeSuccess").addEventListener("click", () => {
    if (!$("successDialog").open) return;
    $("successDialog").close();
    celebrateWithConfetti();
  });
  $("artifactFilter").addEventListener("change", () => renderArtifacts(true));
  $("saveModel").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("saveOracle").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("saveProxy").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("findProxyModels").addEventListener("click", () => loadModels("proxy"));
  $("proxyProvider").addEventListener("change", () => { if ($("proxyProvider").value === "zai") { $("maxOutput").value = Math.max(8192, Number($("maxOutput").value)); $("temperature").value = 1; $("proxyTopP").value = 0.95; $("commandChecks").value = "essential"; } else $("commandChecks").value = "strict"; setModelOptions("proxyNimModel", [], ""); renderModel({...lastModel, logs: []}); if ($("proxyProvider").value !== "unsloth") loadModels("proxy"); });
  $("oracleProvider").addEventListener("change", () => { if ($("oracleProvider").value === "zai" && Number($("oracleReply").value) < 16384) $("oracleReply").value = 16384; setModelOptions("oracleModel", [], ""); renderModel({...lastModel, logs: []}); if ($("oracleProvider").value !== "codex") loadModels("oracle"); });
  for (const id of ["oracleModel", "proxyNimModel", "oracleAccess", "proxyAccess", "studioModel"]) {
    $(id).addEventListener("change", renderSelections);
  }
  $("enableThinking").addEventListener("change", () => {
    if ($("enableThinking").checked && $("proxyProvider").value === "nvidia_nim" &&
        $("proxyNimModel").value.trim() === "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning" &&
        Number($("maxOutput").value) < 8192) $("maxOutput").value = 8192;
  });
  $("htbProfile").addEventListener("click", () => {
    $("networkInput").value = "harp_vpn";
    $("networkPolicy").value = "vpn_bridge";
    showPage("settings");
    $("targetInput").focus();
    toast("Enter the authorized HTB target IP, then save configuration");
  });
  $("runtimeSelect").addEventListener("change", () => {
    if ($("runtimeSelect").value !== "docker") $("networkPolicy").value = "vpn_bridge";
    renderRuntimeFields();
  });
  $("saveConfig").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("dependencyWarning").addEventListener("click", () => {
    renderDependencies(dependencies);
    if (!$("dependencyDialog").open) $("dependencyDialog").showModal();
  });
  $("dependencyDone").addEventListener("click", () => $("dependencyDialog").close());
  $("dependencyDialog").addEventListener("cancel", event => { if (dependencies?.status === "installing" || dependencyPending) event.preventDefault(); });
  $("dependencyRecheck").addEventListener("click", async () => {
    try { renderDependencies(await post("/api/dependencies/check")); await poll(); }
    catch (error) { toast(error.message, true); }
  });
  $("dependencyInstall").addEventListener("click", async () => {
    if (dependencyPending || $("dependencyInstall").disabled) return;
    const key = dependencies?.key;
    dependencyPending = true;
    renderDependencies(dependencies);
    try { await post("/api/dependencies/install", {key}); }
    catch (error) { toast(error.message, true); }
    finally { dependencyPending = false; await poll(); }
  });
  function setModelOptions(id, models, selected) {
    const values = [...new Set([selected, ...models].filter(Boolean))];
    $(id).replaceChildren(new Option("Choose a model", ""), ...values.map(value => new Option(value, value)));
    $(id).value = selected || "";
  }
  async function loadModels(role) {
    const provider = $(role === "proxy" ? "proxyProvider" : "oracleProvider").value;
    if (!["openai", "nvidia_nim", "zai"].includes(provider)) return;
    const id = role === "proxy" ? "proxyNimModel" : "oracleModel";
    const base = $(role === "proxy" ? "proxyOpenaiUrl" : "oracleOpenaiUrl").value.trim();
    try {
      const result = await api(`/api/oracle/models?provider=${provider}&base_url=${encodeURIComponent(base)}`);
      if ($(role === "proxy" ? "proxyProvider" : "oracleProvider").value !== provider || $(role === "proxy" ? "proxyOpenaiUrl" : "oracleOpenaiUrl").value.trim() !== base) return;
      setModelOptions(id, result.models, $(id).value);
      toast(provider === "zai" ? "GLM model presets loaded; account access is checked on first request" : `${result.models.length} models loaded`);
    } catch (error) { toast(error.message, true); }
  }
  $("findNimModels").addEventListener("click", () => loadModels("oracle"));
  const keyProviders = {
    openai: {label: "OpenAI", help: "Used by the OpenAI oracle and proxy. OPENAI_API_KEY takes precedence when set. Daybreak requires access enabled for your API project."},
    zai: {label: "Z.AI", help: "Used by the Z.AI oracle and proxy with the standard API endpoint. ZAI_API_KEY takes precedence when set."},
    nvidia_nim: {label: "NVIDIA NIM", help: "Used by the NVIDIA NIM oracle and proxy. NVIDIA_API_KEY takes precedence when set."},
    unsloth: {label: "Unsloth", help: "Used by the local Unsloth proxy. Paste the API key shown by your Unsloth server. UNSLOTH_API_KEY takes precedence when set."}
  };
  $("apiKeyProvider").addEventListener("change", () => {
    const provider = keyProviders[$("apiKeyProvider").value];
    $("apiKeyValue").value = "";
    $("apiKeyHelp").textContent = provider.help;
    $("saveApiKey").textContent = `Import ${provider.label} key`;
  });
  $("apiKeyForm").addEventListener("submit", async event => {
    event.preventDefault();
    if ($("saveApiKey").disabled) return;
    const provider = $("apiKeyProvider").value;
    const key = $("apiKeyValue").value.trim();
    if (!key) { toast("Paste an API key first", true); return; }
    $("saveApiKey").disabled = true;
    $("apiKeyProvider").disabled = true;
    $("apiKeyValue").disabled = true;
    try {
      const result = await post(`/api/keys/${provider}`, {key});
      $("apiKeyValue").value = "";
      toast(result.message);
      await poll();
    } catch (error) { toast(error.message, true); }
    finally {
      $("saveApiKey").disabled = false;
      $("apiKeyProvider").disabled = false;
      $("apiKeyValue").disabled = false;
    }
  });
  $("startSession").addEventListener("click", async () => {
    if (startPending) return;
    const stopId = $("startSession").dataset.stopId;
    if (stopId) {
      if (confirm("Stop this session? The outcome will remain unknown unless success was verified."))
        action(`/api/sessions/${encodeURIComponent(stopId)}/stop-session`);
      return;
    }
    startPending = true;
    startingAt = Date.now();
    selectedId = "";
    selected = null;
    cursor = 0;
    verboseEvents = [];
    $("activityFeed").replaceChildren(el("div", "empty-state", "Starting reconnaissance…"));
    $("verboseFeed").replaceChildren(el("p", "muted-text", "Waiting for the first command…"));
    showPage("overview");
    window.scrollTo({top: 0, behavior: "instant"});
    renderSummary();
    renderStartStop();
    try {
      await saveConfig(false);
      if (!await action("/api/sessions/start", {mode: $("modeSelect").value,
                                                 fresh_recon: $("freshRecon").checked})) { startPending = false; startingAt = null; }
      else { $("freshRecon").checked = false; rememberInterfaceSettings(); }
    } catch (error) { startPending = false; startingAt = null; toast(error.message, true); }
    renderStartStop();
  });
  $("delegateButton").addEventListener("click", () => {
    const objective = $("objectiveInput").value.trim();
    if (!objective) { toast("Enter a proxy objective", true); return; }
    if (selected && objective !== selected.objective && !confirm("This changes the predeclared objective and will count as human tactical help. Continue?")) return;
    sessionAction("delegate", {objective, steps: Number($("stepsInput").value), unbridled: $("unbridledInput").checked});
  });
  $("stopLocal").addEventListener("click", () => sessionAction("stop"));
  $("resumeOracle").addEventListener("click", () => sessionAction("resume-oracle", {unlimited_budget: $("unlimitedBudgetInput").checked}));
  $("runManual").addEventListener("click", () => {
    const command = $("manualCommand").value.trim();
    if (!command) { toast("Enter a Kali command", true); return; }
    if (!confirm(`Run this command in Kali and record human tactical help?\n\n${command}`)) return;
    sessionAction("terminal", {command});
  });
  $("markSuccess").addEventListener("click", () => sessionAction("success", {evidence: $("successEvidence").value.trim()}));
  $("finishSession").addEventListener("click", () => {
    const outcome = $("finishOutcome").value;
    if (confirm(`Finish this session as ${outcome}?`)) sessionAction("finish", {outcome});
  });
  $("launchModel").addEventListener("click", async () => {
    try { await saveConfig(false); await action("/api/model/start"); }
    catch (error) { toast(error.message, true); }
  });
  $("stopModel").addEventListener("click", () => {
    if (confirm("Stop the Unsloth model launched by this command center?")) action("/api/model/stop");
  });
  $("checkContext").addEventListener("click", async () => {
    try { const data = await api("/api/model/context"); $("actualContext").textContent = Number(data.context).toLocaleString(); toast("Running context checked"); }
    catch (error) { toast(error.message, true); }
  });
  $("approveRoot").addEventListener("click", () => {
    openApprovalDialog(selected?.pending_approval);
  });
  $("cancelRoot").addEventListener("click", () => $("rootDialog").close());
  $("confirmRoot").addEventListener("click", () => {
    const pending = selected?.pending_approval;
    $("rootDialog").close();
    if (pending) sessionAction("approval", {id: pending.id, approved: true});
  });
  $("denyRoot").addEventListener("click", () => {
    const pending = selected?.pending_approval;
    if (pending && confirm(`Deny this exact command?\n\n${pending.command}`)) sessionAction("approval", {id: pending.id, approved: false});
  });

  poll();
  setInterval(poll, 1300);
  setInterval(renderElapsed, 1000);
})();
