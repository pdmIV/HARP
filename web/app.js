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
  let currentFilter = "all";
  let artifactSignature = "";
  let configLoaded = false;
  let pollBusy = false;
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
    $("pageCrumb").textContent = ({overview: "Overview", flags: "Flags", artifacts: "Artifacts", model: "Local model", settings: "Configuration"})[name];
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
      const button = el("button", "session-item" + (session.id === selectedId ? " selected" : ""));
      button.type = "button";
      const top = el("div", "session-top");
      top.append(el("span", "", session.target));
      const marker = session.pending_approval ? "⚠" : session.unseen_flags ? "⚑" : session.flags_found ? "✓" : "";
      top.append(el("span", "session-mini-alert", marker));
      button.append(top, el("div", "session-sub", `${session.mode} · ${session.status} · ${session.id.slice(9,15)}`));
      button.addEventListener("click", () => switchSession(session.id));
      list.append(button);
    }
  }

  function renderModel(model) {
    const running = !!model.listening;
    $("serverStatus").className = "status-pill" + (running ? "" : " muted");
    $("serverStatus").replaceChildren(el("i"), document.createTextNode(running ? ` Model online :${model.port}` : " Model offline"));
    $("modelHealth").className = "status-pill" + (running ? "" : " muted");
    $("modelHealth").textContent = running ? "Listening" : "Offline";
    $("connectionDot").classList.toggle("online", running);
    $("connectionTitle").textContent = running ? "Local model online" : "Command center online";
    $("connectionDetail").textContent = running ? `127.0.0.1:${model.port}` : "Awaiting Unsloth";
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
    const port = new URL(local.base_url).port || "8888";
    const values = {
      studioModel: studio.model || local.model || "", studioPort: studio.port || port,
      studioContext: studio.context || "32768", cacheK: studio.cache_k || "bf16",
      cacheV: studio.cache_v || "bf16", studioParallel: studio.parallel || "1",
      maxInput: local.max_input_tokens || "24000", maxOutput: local.max_tokens || "1024",
      temperature: local.temperature ?? "0.7", targetInput: cfg.target || "",
      networkInput: cfg.network || "", networkPolicy: cfg.network_policy || "internal_lab",
      scanPorts: cfg.scan_ports || "", configObjective: cfg.objective || "",
      containerMemory: cfg.container_memory || "512m", containerCpus: cfg.container_cpus || "1",
      maxSteps: cfg.max_steps || "20", commandTimeout: cfg.command_timeout_seconds || "45",
      objectiveInput: cfg.objective || ""
    };
    for (const [id, value] of Object.entries(values)) $(id).value = value;
    $("enableThinking").checked = !!local.enable_thinking;
    configLoaded = true;
  }

  function configPayload() {
    return {
      studio: {model: $("studioModel").value.trim(), port: Number($("studioPort").value),
               context: Number($("studioContext").value), cache_k: $("cacheK").value,
               cache_v: $("cacheV").value, parallel: Number($("studioParallel").value)},
      local: {max_input_tokens: Number($("maxInput").value), max_tokens: Number($("maxOutput").value),
              temperature: Number($("temperature").value), enable_thinking: $("enableThinking").checked},
      target: $("targetInput").value.trim(), network: $("networkInput").value.trim(),
      network_policy: $("networkPolicy").value, scan_ports: $("scanPorts").value.trim(),
      objective: $("configObjective").value.trim(), container_memory: $("containerMemory").value.trim(),
      container_cpus: Number($("containerCpus").value), max_steps: Number($("maxSteps").value),
      command_timeout_seconds: Number($("commandTimeout").value)
    };
  }

  async function saveConfig(showToast = true) {
    const result = await post("/api/config", configPayload());
    if (showToast) toast("Configuration saved for new sessions");
    return result;
  }

  function eventCategory(event) {
    const kind = event.type || "";
    if (kind === "oracle_plan" || kind === "delegation" || kind === "oracle_terminal") return "oracle";
    if (kind === "local_action" || kind === "local_terminal" || kind === "memory_query") return "local";
    if (kind === "terminal_output" || kind === "approved_root_terminal") return "terminal";
    if (kind.startsWith("root_approval")) return "approval";
    return "system";
  }

  function eventInfo(event) {
    const kind = event.type || "event";
    if (kind === "oracle_plan") return ["Oracle plan", event.plan, ""];
    if (kind === "delegation") return ["Task delegated", `${event.objective} · up to ${event.budget} steps`, ""];
    if (kind === "local_action") {
      const action = event.action || {};
      const command = action.command || action.finding || action.memory_query || "";
      const artifact = action.artifact ? `\nArtifact: ${action.artifact.title} — ${action.artifact.value}` : "";
      return [`Local worker · step ${event.step}`, action.thought || "Action selected", command + artifact];
    }
    if (kind === "terminal_output") return ["Terminal output", event.command || "", event.text || ""];
    if (kind === "local_terminal" || kind === "oracle_terminal" || kind === "approved_root_terminal") {
      const result = event.result || {};
      return [kind === "local_terminal" ? "Local command" : kind === "oracle_terminal" ? "Oracle command" : "Approved root command",
              `Exit ${result.exit_code} · ${result.seconds || 0}s`, result.command || ""];
    }
    if (kind === "deterministic_recon") return ["Reconnaissance complete", `${(event.findings || []).length} open services identified`, ""];
    if (kind === "deterministic_http_probe") return ["HTTP probe", `Port ${event.probe?.port} · status ${event.probe?.status || "unknown"}`, event.probe?.body_excerpt || ""];
    if (kind === "delegation_stopped") return ["Delegation stopped", `Reason: ${(event.reason || "unknown").replaceAll("_", " ")}`, ""];
    if (kind === "artifact_recorded") return [kind === "artifact_recorded" && event.kind === "flag" ? "Flag captured" : "Artifact recorded", `${event.title} · ${event.kind}`, ""];
    if (kind === "verified_success") return ["Success verified", event.evidence || "", ""];
    if (kind === "finish") return ["Session finished", `Outcome: ${event.success}`, ""];
    if (kind.startsWith("root_approval")) return [kind.replaceAll("_", " "), event.source || "Exact root command", event.command || ""];
    if (kind === "context_compaction") return ["Context compacted", `Prompt ${event.prompt_tokens} / ${event.budget_tokens} tokens`, ""];
    if (kind === "operator_stop_requested") return ["Stop requested", "Worker will stop after its current step", ""];
    return [kind.replaceAll("_", " "), "", ""];
  }

  function appendEvents(events) {
    const feed = $("activityFeed");
    if (events.length && feed.querySelector(".empty-state")) feed.replaceChildren();
    const nearBottom = feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 80;
    for (const event of events) {
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
      $("sessionHeading").textContent = "No session selected";
      return;
    }
    const sum = selected.summary;
    $("sessionHeading").textContent = `${sum.target} · ${sum.mode}`;
    $("sessionState").className = "status-pill" + (sum.status === "active" ? "" : " muted");
    $("sessionState").textContent = sum.status.toUpperCase();
    $("metricTools").textContent = sum.terminal_tool_calls ?? "0";
    $("metricModel").textContent = sum.local_model_calls ?? "0";
    $("metricTokens").textContent = ((sum.local_input_tokens || 0) + (sum.local_output_tokens || 0)).toLocaleString();
    const flagCount = Object.values(selected.flags || {}).filter(x => x.found).length;
    $("metricFlags").textContent = `${flagCount} / 2`;
    $("metricOutcome").textContent = sum.success === "yes" ? (flagCount === 2 ? "Success" : "Other result") : sum.success === "no" ? "No" : "Pending";
    $("metricOutcomeNote").textContent = sum.success === "yes" && flagCount < 2 ? "No flag pair recorded" : sum.time_to_success_seconds != null ? `In ${formatDuration(sum.time_to_success_seconds)}` : sum.human_intervention_at ? "Human tactical help recorded" : "Before human tactical help";
    const live = document.querySelector(".live-indicator");
    live.classList.toggle("muted", sum.status !== "active");
    live.replaceChildren(el("i"), document.createTextNode(sum.status === "active" ? " LIVE" : " REPLAY"));
    const active = sum.status === "active";
    for (const id of ["delegateButton", "stopLocal", "runManual", "markSuccess", "finishSession"]) $(id).disabled = !active;
    if (sum.mode === "local-only") $("runManual").disabled = true;
    if (sum.mode === "frontier-only") $("delegateButton").disabled = true;
    $("oraclePlan").textContent = selected.activity.oracle_plan || "Codex will publish a plan after reviewing reconnaissance.";
    const local = selected.activity.local_action;
    $("localAction").textContent = local ? `${local.thought || "Working"}${local.command ? " · " + local.command : ""}${sum.last_delegate_stop ? " · Stopped: " + sum.last_delegate_stop.replaceAll("_", " ") : ""}` : "Awaiting a delegated objective.";
    const ports = (selected.recon || []).map(x => `${x.port}/${x.service || "unknown"}`);
    $("reconSummary").textContent = ports.length ? ports.join(" · ") : "No open services reported yet.";
    const approval = selected.pending_approval;
    $("approvalCard").classList.toggle("hidden", !approval);
    if (approval) {
      $("approvalDescription").textContent = `${approval.source === "local" ? "Local worker" : "Oracle"} requested a command requiring root privileges.`;
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
    if (!selected) return;
    const seconds = selected.summary.status === "active" ? Date.now() / 1000 - selected.started_epoch : selected.duration_seconds;
    $("metricElapsed").textContent = formatDuration(seconds);
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
      if (selectedId && !sessions.some(x => x.id === selectedId)) {
        selectedId = "";
        cursor = 0;
      }
      if (!selectedId && sessions.length) {
        selectedId = sessions[0].id;
        localStorage.setItem("harpSelectedSession", selectedId);
        cursor = 0;
      }
      fillConfig(data.config);
      renderModel(data.model);
      if (data.selected && data.selected.id === selectedId) {
        selected = data.selected;
        cursor = selected.event_cursor;
        appendEvents(selected.events || []);
        renderSummary();
      }
      renderSessions();
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
        if (job.status === "error") toast(`${job.name}: ${job.detail}`, true);
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

  function sessionAction(name, body = {}) {
    if (!selectedId) { toast("Select or start a session first", true); return; }
    return action(`/api/sessions/${encodeURIComponent(selectedId)}/${name}`, body);
  }

  document.querySelectorAll(".nav-item").forEach(item => item.addEventListener("click", () => showPage(item.dataset.page)));
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
  $("htbProfile").addEventListener("click", () => {
    $("networkInput").value = "harp_vpn";
    $("networkPolicy").value = "vpn_bridge";
    showPage("settings");
    $("targetInput").focus();
    toast("Enter the authorized HTB target IP, then save configuration");
  });
  $("saveConfig").addEventListener("click", async () => { try { await saveConfig(); } catch (error) { toast(error.message, true); } });
  $("startSession").addEventListener("click", async () => {
    try { await saveConfig(false); await action("/api/sessions/start", {mode: $("modeSelect").value}); }
    catch (error) { toast(error.message, true); }
  });
  $("delegateButton").addEventListener("click", () => {
    const objective = $("objectiveInput").value.trim();
    if (!objective) { toast("Enter a local objective", true); return; }
    if (selected && objective !== selected.objective && !confirm("This changes the predeclared objective and will count as human tactical help. Continue?")) return;
    sessionAction("delegate", {objective, steps: Number($("stepsInput").value)});
  });
  $("stopLocal").addEventListener("click", () => sessionAction("stop"));
  $("runManual").addEventListener("click", () => {
    const command = $("manualCommand").value.trim();
    if (!command) { toast("Enter a Kali command", true); return; }
    if (!confirm(`Run this command in Kali and record human tactical help?\n\n${command}`)) return;
    sessionAction("terminal", {command});
  });
  $("markSuccess").addEventListener("click", () => sessionAction("success", {evidence: $("successEvidence").value.trim()}));
  $("finishSession").addEventListener("click", () => {
    const outcome = $("finishOutcome").value;
    if (confirm(`Finish this session as ${outcome} and remove its Kali container?`)) sessionAction("finish", {outcome});
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
