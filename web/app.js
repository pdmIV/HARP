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
  let selectedId = localStorage.getItem("harpSelectedSession") || "";
  let selected = null;
  let sessions = [];
  let cursor = 0;
  let modelCursor = 0;
  let lastModel = null;
  let budgetSessionId = "";
  let currentFilter = "all";
  let artifactSignature = "";
  let configLoaded = false;
  let pollBusy = false;
  let startPending = false;
  let startingAt = null;
  let verboseEvents = [];
  let seenPending = false;
  let toastTimer;

  const preferredTheme = localStorage.getItem("harpTheme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.dataset.theme = preferredTheme;
  $("themeIcon").textContent = preferredTheme === "dark" ? "☀" : "☾";

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

  const post = (path, body = {}) => api(path, {method: "POST", body: JSON.stringify(body)});
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
    if (!id || id === selectedId) return;
    selectedId = id;
    localStorage.setItem("harpSelectedSession", id);
    selected = null;
    cursor = 0;
    artifactSignature = "";
    $("activityFeed").replaceChildren();
    verboseEvents = [];
    $("verboseFeed").replaceChildren();
    $("objectiveInput").value = "";
    poll();
  }

  function showPage(name) {
    if (name === "flags" && selected && !Object.values(selected.flags || {}).some(x => x.unseen)) {
      const unseenSession = sessions.find(s => s.unseen_flags > 0);
      if (unseenSession && unseenSession.id !== selectedId) switchSession(unseenSession.id);
    }
    currentPage = name;
    document.querySelectorAll(".page").forEach(page => page.classList.toggle("active", page.dataset.panel === name));
    document.querySelectorAll(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.page === name));
    $("pageCrumb").textContent = ({overview: "Overview", verbose: "Verbose", flags: "Flags", artifacts: "Artifacts", model: "Proxy model", settings: "Configuration"})[name];
    if (name === "verbose") renderVerbose();
    if (name === "flags") acknowledgeFlags();
    if (name === "artifacts") renderArtifacts(true);
  }

  function renderSessions() {
    const list = $("sessionList");
    list.replaceChildren();
    if (!sessions.length) {
      list.append(el("div", "empty-small", "No sessions yet"));
      return;
    }
    for (const session of sessions) {
      const row = el("div", "session-row" + (session.id === selectedId ? " selected" : ""));
      const button = el("button", "session-item");
      button.type = "button";
      const top = el("div", "session-top");
      top.append(el("span", "", session.target));
      const marker = session.pending_approval ? "⚠" : session.unseen_flags ? "⚑" : session.flags_found ? "✓" : "";
      top.append(el("span", "session-mini-alert", marker));
      button.append(top, el("div", "session-sub", `${session.mode} · ${session.status} · ${session.id.slice(9,15)}`));
      button.addEventListener("click", () => switchSession(session.id));
      row.append(button);
      if (session.status === "finished") {
        const remove = el("button", "session-delete", "×");
        remove.type = "button";
        remove.title = "Delete session and logs";
        remove.setAttribute("aria-label", `Delete session and logs for ${session.target}`);
        remove.addEventListener("click", () => deleteFinishedSession(session));
        row.append(remove);
      }
      list.append(row);
    }
  }

  function renderStartStop() {
    const active = sessions.find(session => session.id === selectedId && session.status === "active") ||
                   sessions.find(session => session.status === "active");
    const recon = sessions.find(session => session.status === "recon");
    const running = active || recon;
    const button = $("startSession");
    if (running) startPending = false;
    button.classList.toggle("danger", !!running);
    button.classList.toggle("primary", !running);
    button.replaceChildren(document.createTextNode(running ? "■ Stop session" : startPending ? "Starting session…" : "＋ Start session"));
    button.disabled = startPending && !running;
    button.dataset.stopId = running?.id || "";
    $("modeSelect").disabled = !!running;
  }

  function deleteFinishedSession(session) {
    if (session.status !== "finished") return;
    if (!confirm(`Permanently delete session ${session.id}, including logs, artifacts, and captured files?`)) return;
    action(`/api/sessions/${encodeURIComponent(session.id)}/delete`);
  }

  function renderModel(model) {
    lastModel = model;
    const running = !!model.listening;
    $("temperature").disabled = $("proxyProvider").value === "openai";
    $("enableThinking").disabled = $("proxyProvider").value === "openai";
    const nimProxy = $("proxyProvider").value !== "unsloth";
    const hostedLabel = $("proxyProvider").value === "openai" ? "OpenAI" : "NIM";
    document.querySelectorAll(".openai-proxy").forEach(x => x.classList.toggle("hidden", $("proxyProvider").value !== "openai"));
    document.querySelectorAll(".openai-oracle").forEach(x => x.classList.toggle("hidden", $("oracleProvider").value !== "openai"));
    $("unslothSettings").classList.toggle("hidden", nimProxy);
    $("unslothLog").classList.toggle("hidden", nimProxy);
    $("proxyNimModel").disabled = !nimProxy;
    $("serverStatus").className = "status-pill" + (running && !nimProxy ? "" : " muted");
    $("serverStatus").replaceChildren(el("i"), document.createTextNode(nimProxy ? ` ${hostedLabel} proxy selected` : running ? ` Unsloth online :${model.port}` : " Unsloth offline"));
    $("modelHealth").className = "status-pill" + (running ? "" : " muted");
    $("modelHealth").textContent = running ? "Listening" : "Offline";
    $("connectionDot").classList.toggle("online", running && !nimProxy);
    $("connectionTitle").textContent = nimProxy ? `${hostedLabel} proxy selected` : running ? "Unsloth proxy online" : "Command center online";
    $("connectionDetail").textContent = nimProxy ? "Hosted model" : running ? `127.0.0.1:${model.port}` : "Awaiting Unsloth";
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

  function renderBenchmarkResults(results) {
    const container = $("benchmarkResults");
    container.replaceChildren();
    for (const item of results) {
      const row = el("div", "benchmark-row");
      row.append(el("span", "benchmark-model", item.model),
                 el("span", item.usable ? "benchmark-time" : "benchmark-failed",
                    item.usable ? `${item.seconds}s · usable plan` : `${item.status.replaceAll("_", " ")} · ${item.seconds}s`));
      if (item.usable) {
        const select = el("button", "button secondary", "Use model");
        select.type = "button";
        select.addEventListener("click", async () => {
          $("oracleProvider").value = "nvidia_nim";
          setModelOptions("oracleModel", [item.model], item.model);
          try { await saveConfig(false); toast(`Oracle model saved: ${item.model}`); }
          catch (error) { toast(error.message, true); }
        });
        row.append(select);
      }
      container.append(row);
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
      temperature: local.temperature ?? "0.7", targetInput: cfg.target || "",
      runtimeSelect: cfg.runtime || "docker", wslDistro: cfg.wsl_distro || "kali-linux",
      wslUser: cfg.wsl_user || "kali", networkInput: cfg.network || "",
      networkPolicy: cfg.network_policy || "internal_lab",
      scanPorts: cfg.scan_ports || "", configObjective: cfg.objective || "",
      containerMemory: cfg.container_memory || "512m", containerCpus: cfg.container_cpus || "1",
      maxSteps: cfg.max_steps || "20", commandTimeout: cfg.command_timeout_seconds || "45",
      objectiveInput: cfg.objective || ""
    };
    for (const [id, value] of Object.entries(values)) $(id).value = value;
    $("enableThinking").checked = !!local.enable_thinking;
    $("proxyProvider").value = local.provider || "unsloth";
    setModelOptions("proxyNimModel", [], local.provider !== "unsloth" ? local.model || "" : "");
    $("proxyOpenaiUrl").value = local.provider === "openai" ? local.base_url || "https://api.openai.com/v1" : "https://api.openai.com/v1";
    $("proxyAccess").value = local.access_program || "daybreak_blue";
    const oracle = cfg.oracle || {};
    $("oracleProvider").value = oracle.provider || "codex";
    setModelOptions("oracleModel", [], oracle.model || "");
    $("oracleOpenaiUrl").value = oracle.base_url || "https://api.openai.com/v1";
    $("oracleAccess").value = oracle.access_program || "daybreak_blue";
    $("benchmarkCandidates").value = oracle.model || "";
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

  function configPayload() {
    return {
      studio: {model: $("studioModel").value.trim(), port: Number($("studioPort").value),
               context: Number($("studioContext").value), cache_k: $("cacheK").value,
               cache_v: $("cacheV").value, parallel: Number($("studioParallel").value)},
      local: {provider: $("proxyProvider").value, model: $("proxyNimModel").value.trim(),
              base_url: $("proxyOpenaiUrl").value.trim(), access_program: $("proxyAccess").value,
              ...($("proxyProvider").value === "openai" ? cacheConfig("proxy") : {}),
              max_input_tokens: Number($("maxInput").value), max_tokens: Number($("maxOutput").value),
              temperature: Number($("temperature").value), enable_thinking: $("enableThinking").checked},
      target: $("targetInput").value.trim(), runtime: $("runtimeSelect").value,
      wsl_distro: $("wslDistro").value.trim(), wsl_user: $("wslUser").value.trim(),
      network: $("networkInput").value.trim(),
      network_policy: $("networkPolicy").value, scan_ports: $("scanPorts").value.trim(),
      objective: $("configObjective").value.trim(), container_memory: $("containerMemory").value.trim(),
      container_cpus: Number($("containerCpus").value), max_steps: Number($("maxSteps").value),
      command_timeout_seconds: Number($("commandTimeout").value),
      oracle: {provider: $("oracleProvider").value, model: $("oracleModel").value.trim(),
               base_url: $("oracleOpenaiUrl").value.trim(), access_program: $("oracleAccess").value,
               ...($("oracleProvider").value === "openai" ? cacheConfig("oracle") : {}),
               max_cycles: Number($("oracleCycles").value), steps_per_cycle: Number($("oracleSteps").value),
               unlimited_budget: $("oracleUnlimited").checked, max_tokens: $("oracleProvider").value === "openai" ? 4096 : 1024}
    };
  }

  async function saveConfig(showToast = true) {
    const result = await post("/api/config", configPayload());
    if (showToast) toast("Configuration saved for new sessions");
    return result;
  }

  function eventCategory(event) {
    const kind = event.type || "";
    if (kind === "oracle_plan" || kind === "delegation" || kind === "oracle_terminal" ||
        kind === "oracle_nim_recovery" || kind === "oracle_nim_probe" ||
        kind === "oracle_nim_probe_rejected" || kind === "oracle_nim_resumed") return "oracle";
    if (kind === "local_action" || kind === "local_terminal" || kind === "memory_query") return "local";
    if (kind === "terminal_output" || kind === "approved_root_terminal") return "terminal";
    if (kind.startsWith("root_approval")) return "approval";
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
    if (kind === "recon_failed") return ["Reconnaissance failed", event.error || "Startup failed", ""];
    if (kind === "recon_cancelled") return ["Reconnaissance stopped", "Stopped after the current command", ""];
    if (kind === "oracle_plan") return ["Oracle plan", event.plan, ""];
    if (kind === "delegation") return ["Task delegated", `${event.objective} · ${event.unbridled ? "unbridled" : event.unlimited_budget ? "no step budget" : `up to ${event.budget} steps`}`, ""];
    if (kind === "oracle_budget_changed") return ["Oracle budget changed", event.unlimited_budget ? "Cycle and proxy step/model-call budgets removed" : "Configured budgets restored", ""];
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
    if (kind === "oracle_nim_stopped") return ["Oracle stopped", `Reason: ${(event.reason || "unknown").replaceAll("_", " ")}`, event.detail || ""];
    if (kind === "oracle_nim_usage") return ["Oracle response", `${event.input_tokens ?? "?"} input / ${event.output_tokens ?? "?"} output tokens / ${event.cached_input_tokens ?? 0} cached / ${event.cache_write_tokens ?? 0} cache writes / ${event.seconds ?? "?"}s`, event.cost_basis ? (event.estimated_usd == null ? "Cost unknown: configure token prices" : `Estimated $${event.estimated_usd.toFixed(6)} before account allowances`) : ""];
    if (kind === "oracle_nim_request") return ["Oracle planning", `Request sent to ${event.model} · cycle ${event.cycle}`, ""];
    if (kind === "oracle_nim_recovery") return ["Oracle reviewing failure", `Worker stopped: ${(event.reason || "unknown").replaceAll("_", " ")} · correction ${event.attempt}`, ""];
    if (kind === "oracle_nim_probe") return ["Oracle probe", "One scoped, read-only command", event.command || ""];
    if (kind === "oracle_nim_resumed") return ["Oracle resumed", "Continuing this session's plan and cycle budget", ""];
    if (kind === "oracle_nim_probe_rejected") return ["Oracle probe needs correction", event.reason || "Probe check failed", `Correction ${event.attempt}`];
    if (kind === "local_command_rejected") return ["Command check rejected", event.reason || "Invalid command", event.command || ""];
    if (kind === "local_command_check") return ["Shell syntax checked", `Exit ${event.result?.exit_code ?? "?"}`, event.result?.exit_code ? event.result?.output || "" : ""];
    if (kind === "local_response_mode_changed") return ["Proxy reply retry", "Retrying a malformed reply with stricter settings", ""];
    if (kind === "delegation_stopped") return ["Delegation stopped", `Reason: ${(event.reason || "unknown").replaceAll("_", " ")}`, ""];
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
    const row = el("details", "verbose-entry");
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
      $("cacheUsage").textContent = "No API usage recorded.";
      $("apiCost").textContent = "Estimates require configured token prices.";
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
      renderElapsed();
      return;
    }
    const sum = selected.summary;
    $("sessionHeading").textContent = `${sum.target} · ${sum.mode}`;
    $("sessionState").className = "status-pill" + (["active", "recon"].includes(sum.status) ? "" : " muted");
    $("sessionState").textContent = sum.status.toUpperCase();
    $("metricTools").textContent = sum.terminal_tool_calls ?? "0";
    $("metricModel").textContent = sum.local_model_calls ?? "0";
    $("metricTokens").textContent = ((sum.local_input_tokens || 0) + (sum.local_output_tokens || 0)).toLocaleString();
    const cacheText = (name, input, cached, writes) => `${name}: ${(cached || 0).toLocaleString()} cached / ${(input || 0).toLocaleString()} input (${input ? (100 * (cached || 0) / input).toFixed(1) : "0"}% hit), ${(writes || 0).toLocaleString()} cache writes`;
    $("cacheUsage").textContent = cacheText("Proxy", sum.local_input_tokens, sum.local_cached_input_tokens, sum.local_cache_write_tokens) + " | " + cacheText("Oracle", sum.oracle_input_tokens, sum.oracle_cached_input_tokens, sum.oracle_cache_write_tokens);
    const costText = (value, calls) => !calls ? "no calls" : value == null ? "unknown prices" : `$${value.toFixed(6)}`;
    $("apiCost").textContent = `Estimated before account allowances: Proxy ${costText(sum.local_estimated_usd, sum.local_model_calls)} | Oracle ${costText(sum.oracle_estimated_usd, sum.oracle_model_calls)}`;
    const flagCount = Object.values(selected.flags || {}).filter(x => x.found).length;
    $("metricFlags").textContent = `${flagCount} / 2`;
    $("metricOutcome").textContent = sum.status === "recon" ? "Scanning" : sum.success === "yes" ? (flagCount === 2 ? "Success" : "Other result") : sum.success === "no" ? "No" : "Pending";
    $("metricOutcomeNote").textContent = sum.status === "recon" ? "Reconnaissance in progress" : sum.success === "yes" && flagCount < 2 ? "No flag pair recorded" : sum.time_to_success_seconds != null ? `In ${formatDuration(sum.time_to_success_seconds)}` : sum.human_intervention_at ? "Human tactical help recorded" : "Before human tactical help";
    const live = document.querySelector(".live-indicator");
    live.classList.toggle("muted", !["active", "recon"].includes(sum.status));
    live.replaceChildren(el("i"), document.createTextNode(["active", "recon"].includes(sum.status) ? " LIVE" : " REPLAY"));
    $("reconProgress").classList.toggle("hidden", sum.status !== "recon");
    $("reconProgressTitle").textContent = sum.recon_stage || "Reconnaissance";
    $("reconStage").textContent = sum.recon_command ? "Running now" : "Preparing the next command";
    $("reconCurrentCommand").textContent = sum.recon_command || "Waiting for the next command";
    $("verboseSession").textContent = `${sum.target} · ${sum.mode}`;
    $("verboseStage").textContent = sum.status === "recon" ? `Reconnaissance: ${sum.recon_stage || "Preparing Kali"}` : `Session ${sum.status}`;
    const active = sum.status === "active";
    for (const id of ["delegateButton", "stopLocal", "runManual", "markSuccess", "finishSession"]) $(id).disabled = !active;
    const canResumeOracle = active && ["nvidia_nim", "openai"].includes(selected.oracle_provider) && !!selected.activity.oracle_stopped;
    $("resumeOracle").classList.toggle("hidden", !canResumeOracle);
    $("resumeOracle").disabled = !canResumeOracle;
    if (document.activeElement !== $("stepsInput")) $("stepsInput").value = selected.delegation_limit || 20;
    if (sum.mode === "local-only") $("runManual").disabled = true;
    if (sum.mode === "frontier-only") $("delegateButton").disabled = true;
    $("unlimitedBudgetRow").classList.toggle("hidden", !["nvidia_nim", "openai"].includes(selected.oracle_provider));
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
      $("approvalDescription").textContent = `${approval.source === "local" ? "Proxy model" : "Oracle"} requested a command requiring root privileges.`;
      $("approvalCommand").textContent = approval.command;
    }
    if (document.activeElement !== $("objectiveInput") && !$("objectiveInput").value.trim()) $("objectiveInput").value = selected.objective || "";
    renderElapsed();
    renderFlags();
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
    const seconds = live ? Date.now() / 1000 - selected.started_epoch : selected.duration_seconds;
    $("metricElapsed").textContent = formatDuration(seconds);
    $("verboseElapsed").textContent = formatDuration(seconds);
    $("reconClock").textContent = formatDuration(selected.summary.status === "recon"
      ? Date.now() / 1000 - selected.started_epoch : selected.summary.recon_elapsed_seconds);
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
        const download = el("button", "button secondary artifact-download", `↓ Download ${item.attachment.filename}`);
        download.addEventListener("click", () => downloadAttachment(item));
        card.append(download);
      }
      grid.append(card);
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
    if (seenPending || !selectedId || !selected || !Object.values(selected.flags || {}).some(x => x.unseen)) return;
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
    if (pollBusy) return;
    pollBusy = true;
    try {
      const query = new URLSearchParams({session: selectedId, cursor: String(cursor), model_cursor: String(modelCursor)});
      const data = await api(`/api/state?${query}`);
      sessions = data.sessions || [];
      if (startPending) {
        const reconSession = sessions.find(x => x.status === "recon");
        if (reconSession && reconSession.id !== selectedId) switchSession(reconSession.id);
      }
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
      renderModel(data.model);
      if (data.selected && data.selected.id === selectedId) {
        selected = data.selected;
        cursor = selected.event_cursor;
        appendEvents(selected.events || []);
        renderSummary();
      }
      renderSessions();
      renderStartStop();
      updateBadges();
      if (!data.selected && selectedId) setTimeout(poll, 50);
    } catch (error) {
      if (error.message === "Session not found" || error.message === "Invalid session ID") {
        selectedId = "";
        localStorage.removeItem("harpSelectedSession");
        cursor = 0;
      }
      $("connectionTitle").textContent = "Connection unavailable";
      $("connectionDetail").textContent = error.message;
      $("connectionDot").classList.remove("online");
      if (!token) toast(error.message, true);
    } finally { pollBusy = false; }
  }

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
          if (job.name === "NIM speed test") renderBenchmarkResults(job.result?.results || []);
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

  function sessionAction(name, body = {}) {
    if (!selectedId) { toast("Select or start a session first", true); return; }
    return action(`/api/sessions/${encodeURIComponent(selectedId)}/${name}`, body);
  }

  document.querySelectorAll(".nav-item").forEach(item => item.addEventListener("click", () => showPage(item.dataset.page)));
  $("openVerbose").addEventListener("click", () => showPage("verbose"));
  $("verboseFilter").addEventListener("change", renderVerbose);
  $("verboseFollow").addEventListener("change", () => { if ($("verboseFollow").checked) $("verboseFeed").scrollTop = $("verboseFeed").scrollHeight; });
  $("themeToggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("harpTheme", next);
    $("themeIcon").textContent = next === "dark" ? "☀" : "☾";
  });
  $("refreshSessions").addEventListener("click", poll);
  document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
    currentFilter = button.dataset.filter;
    document.querySelectorAll(".filter").forEach(x => x.classList.toggle("active", x === button));
    document.querySelectorAll(".event").forEach(x => { x.hidden = currentFilter !== "all" && x.dataset.category !== currentFilter; });
  }));
  $("artifactSearch").addEventListener("input", () => renderArtifacts(true));
  $("artifactFilter").addEventListener("change", () => renderArtifacts(true));
  $("saveModel").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("saveProxy").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("findProxyModels").addEventListener("click", () => loadModels("proxy"));
  $("proxyProvider").addEventListener("change", () => { setModelOptions("proxyNimModel", [], ""); renderModel({...lastModel, logs: []}); if ($("proxyProvider").value !== "unsloth") loadModels("proxy"); });
  $("oracleProvider").addEventListener("change", () => { setModelOptions("oracleModel", [], ""); renderModel({...lastModel, logs: []}); if ($("oracleProvider").value !== "codex") loadModels("oracle"); });
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
  $("saveConfig").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("saveNimKey").addEventListener("click", async () => {
    try { const result = await post("/api/oracle/key", {key: $("nimKey").value.trim()}); $("nimKey").value = ""; toast(result.message); }
    catch (error) { toast(error.message, true); }
  });
  function setModelOptions(id, models, selected) {
    const values = [...new Set([selected, ...models].filter(Boolean))];
    $(id).replaceChildren(new Option("Choose a model", ""), ...values.map(value => new Option(value, value)));
    $(id).value = selected || "";
  }
  async function loadModels(role) {
    const provider = $(role === "proxy" ? "proxyProvider" : "oracleProvider").value;
    if (!["openai", "nvidia_nim"].includes(provider)) return;
    const id = role === "proxy" ? "proxyNimModel" : "oracleModel";
    const base = $(role === "proxy" ? "proxyOpenaiUrl" : "oracleOpenaiUrl").value.trim();
    try {
      const result = await api(`/api/oracle/models?provider=${provider}&base_url=${encodeURIComponent(base)}`);
      if ($(role === "proxy" ? "proxyProvider" : "oracleProvider").value !== provider || $(role === "proxy" ? "proxyOpenaiUrl" : "oracleOpenaiUrl").value.trim() !== base) return;
      setModelOptions(id, result.models, $(id).value);
      toast(`${result.models.length} models loaded`);
    } catch (error) { toast(error.message, true); }
  }
  $("findNimModels").addEventListener("click", () => loadModels("oracle"));
  $("openaiKeyFile").addEventListener("change", async () => {
    const file = $("openaiKeyFile").files[0];
    if (!file) return;
    if (file.size > 4096) { toast("Choose a text file containing only the API key", true); return; }
    $("openaiKey").value = (await file.text()).trim();
  });
  $("saveOpenaiKey").addEventListener("click", async () => {
    try {
      const result = await post("/api/openai/key", {key: $("openaiKey").value.trim()});
      $("openaiKey").value = ""; $("openaiKeyFile").value = ""; toast(result.message);
      if ($("oracleProvider").value === "openai") loadModels("oracle");
      if ($("proxyProvider").value === "openai") loadModels("proxy");
    } catch (error) { toast(error.message, true); }
  });
  $("runBenchmark").addEventListener("click", async () => {
    const models = $("benchmarkCandidates").value.split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    if (!models.length || models.length > 5) { toast("Enter one to five model IDs", true); return; }
    $("benchmarkResults").replaceChildren(el("p", "muted-text", "Testing synthetic plans; slow models may take up to 90 seconds."));
    await action("/api/oracle/benchmark", {models});
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
      if (!await action("/api/sessions/start", {mode: $("modeSelect").value})) { startPending = false; startingAt = null; }
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
    if (!selected?.pending_approval) return;
    $("dialogCommand").textContent = selected.pending_approval.command;
    $("rootDialog").showModal();
  });
  $("cancelRoot").addEventListener("click", () => $("rootDialog").close());
  $("confirmRoot").addEventListener("click", () => {
    const pending = selected?.pending_approval;
    $("rootDialog").close();
    if (pending) sessionAction("approval", {id: pending.id, approved: true});
  });
  $("denyRoot").addEventListener("click", () => {
    const pending = selected?.pending_approval;
    if (pending && confirm(`Deny this exact root command?\n\n${pending.command}`)) sessionAction("approval", {id: pending.id, approved: false});
  });

  poll();
  setInterval(poll, 1300);
  setInterval(renderElapsed, 1000);
})();
