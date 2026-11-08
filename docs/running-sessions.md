# Running sessions

[Home](../README.md) · [Setup](setup.md) · [Configuration](configuration.md) · [Running sessions](running-sessions.md) · [Host protection](host-protection.md) · [Evaluation](evaluation.md)

## Start with a hosted oracle

1. Launch `python harp_web.py` from the repository root.
2. Import credentials in **API Keys**.
3. Select OpenAI, Z.AI, or NVIDIA NIM in **Oracle model**, load models, choose one, and save.
4. Configure and save the worker in **Proxy model**.
5. Set the exact authorized target and Kali runtime in **Configuration**, then save.
6. Choose **Hybrid** on Overview and click **Start session**. HARP reuses completed reconnaissance for the same target and scan environment when available; otherwise it scans before the hosted oracle starts planning. Select **Refresh reconnaissance** to scan again.

Review the event stream, terminal evidence, and approval requests. **Resume oracle** continues a stopped hosted session using its existing reconnaissance. API access errors must be resolved before resuming.

## Start with Codex as oracle

The Codex chat is the frontier-model oracle; the web command center is the live monitor and approval surface; Unsloth, NIM, or OpenAI serves the proxy model. HARP does not need an OpenAI API key for this route.

1. Prepare your selected Kali runtime using the [setup guide](setup.md) and connect the authorized VPN when needed. Docker Desktop is needed only for Docker mode.
2. In the ChatGPT desktop app, open **Codex** on this trusted local project folder and start a new Codex chat. Choose an eligible GPT-6 model and enable or verify Daybreak if your account offers it. Daybreak is an access setting, not necessarily a separate model name. Confirm that the `harp` MCP server is available; `codex mcp list` also reports its configured status. If you just changed `.codex/config.toml`, reopen the project or restart Codex.
3. Tell Codex **"Launch HARP."** It calls `launch_control_center`, which starts or reopens the web command center in your browser. Codex then waits for you to start a Hybrid session in the browser; it does not start a separate run.
4. In **Oracle model**, select **Codex via MCP** and save. In **Proxy model**, choose Unsloth, NIM, or OpenAI. For Unsloth, enter its model ID and context/KV-cache settings, then select **Launch model**. An already running server is reused. HARP captures a generated Unsloth key and encrypts it for your Windows account. If you started Unsloth separately, import its key in **API Keys**. For NIM, select its model and import the NVIDIA key in **API Keys**. Keep keys out of chat.
5. In **Configuration**, select **Use HTB VPN profile**, enter the exact authorized target IP, and save. Choose **Hybrid** on Overview and click **Start session**. HARP prepares the selected runtime and uses saved reconnaissance if available for that target and scan environment; otherwise it performs deterministic port discovery and service detection. Select **Refresh reconnaissance** if the target may have changed. Docker uses its dedicated bridge and cached Kali image. WSL uses nonroot TCP connect scans; VPN scans use bounded packet rates. No proxy-model request happens before reconnaissance is available. The new run appears in the session list.
6. Codex's `wait_for_session` tool picks up that run and its reconnaissance. Codex publishes a concise operator plan, delegates one bounded task at a time, reviews the resulting evidence and stop reason, then plans the next task until the flags are verified or a stopping condition is reached. Keep the browser open to monitor events and approve commands.

For Codex to return automatically between delegations, configure a Codex heartbeat for this chat. A heartbeat is optional and is not started by HARP; if enabled, it should inspect the active Hybrid session, remain quiet while a delegation runs, and resume the evidence, plan, delegate cycle when work is ready. The **Unbridled** checkbox removes step, model-call, duplicate-command, repeated-output, and unproductive-command stops for one manual delegation. The operator stop control, root approval flow, invalid-reply handling, and evidence checks still apply.

The `.codex/config.toml` in this checkout names `S:\HARP` explicitly. If you clone the repository elsewhere, update its `args` and `cwd` paths to that clone before opening Codex. An ordinary ChatGPT chat without this local Codex workspace and MCP server cannot operate HARP through these tools.

## Web command center and CLI

Launch the local web command center from PowerShell:

```powershell
python harp_web.py
```

The launcher opens a browser on `127.0.0.1:8765`. Codex can launch it through `launch_control_center`; the direct Python command remains available. The control API requires a private token held in that browser tab; other pages cannot control HARP merely by reaching localhost. The interface has light, dark, and AMOLED Dark themes, responsive layouts, and side navigation for Overview, Verbose, Flags, Artifacts, Oracle model, Proxy model, API Keys, and Configuration.

**Overview** follows each session's event log, showing deterministic recon, explicit oracle plan updates, delegated objectives, proxy model actions and short stated reasons, terminal output, approvals, and outcomes. It also shows elapsed time, model calls, terminal calls, token usage, and flag progress. Codex's private reasoning is not available to the app; the project MCP tool `record_oracle_plan` publishes a concise operator-facing plan, and [AGENTS.md](../AGENTS.md) tells Codex to use it when the strategy changes.

The **Stop session** button requests a stop after the current command, ends the active run, and removes its Kali container in Docker mode. WSL sessions leave their Kali workspace on disk. Finished sessions can be deleted from the Outcome card or session list; deletion permanently removes the HARP session record, logs, artifacts, and captured files. It does not remove a WSL workspace. The configured proxy step limit applies afresh to each delegation from an oracle plan unless unlimited budget is selected. Cumulative proxy steps and model calls remain session statistics.

**Flags** shows the actual `user.txt` and `root.txt` values. An alert blinks in the side navigation while a newly captured flag is unseen, and opening Flags acknowledges it. A successful file-reading command that names exactly one flag file and returns a line containing only one 32-character hexadecimal value is captured automatically, including NetExec's service/host-prefixed stdout. When both flags have terminal evidence, HARP timestamps verified success, stops delegation, and finishes the session automatically. The timer stops and a green celebration dialog appears. Other flag formats can be recorded with the evidence-backed `record_artifact` MCP tool.

**Artifacts** shows credentials, document excerpts, flags, and other evidence with source commands. Values are visible in full. The proxy model may nominate an artifact, but HARP records it only when its exact value appears in terminal or deterministic HTTP probe output. Codex can use `record_artifact` for an evidence-backed item it identifies. For a regular file under the session's Kali workspace, `capture_document` preserves up to 8 MiB through the selected runtime, records a text preview and SHA-256, and adds a download button to the panel. Binary files are available as downloads and are not rendered inline. Artifact proposals are checked against existing evidence and again after their accompanying command completes, so matching evidence is registered before the next model request. The dashboard displays registered artifacts on its next live poll (normally within 1.3 seconds).

**Oracle model** configures the planner. **Proxy model** selects Unsloth, NIM, Z.AI, or OpenAI and sets HARP's prompt and reply caps. Unsloth settings include API port, context, K/V cache types, parallel slots, and thinking mode. **Launch model** starts Unsloth with server-side tools disabled. Its generated API key is captured, encrypted for the current Windows account, and redacted from process logs. **Configuration** sets the target, Kali runtime, network policy, scan ports, and limits for new sessions. A changed objective or manually entered Kali command is recorded as human tactical help; approving a pending root command is not.

If a model is already listening on the selected port, the app monitors it without starting another. If Codex requests root while the web app is active, approve the exact command in the Codex prompt and then in the app. If the web app is closed, the Codex approval remains the gate. The app can also approve a proxy model's pending root request, after which delegation can continue. Stopping the Python web process stops only an Unsloth model it launched itself.

**Keep Unsloth's server-side tools off for HARP.** The example request with `enable_tools: true`, `enabled_tools: ["python", "terminal"]`, and `permission_mode: "off"` would give the model tools outside HARP's Kali container. HARP explicitly sends `enable_tools: false` and an empty tool list. If you launch Unsloth from its CLI, `--disable-tools` is an additional process-level safeguard. [Unsloth documents these controls](https://unsloth.ai/docs/basics/api).

```powershell
python harp.py start --mode hybrid
python harp.py inspect runs\SESSION_DIRECTORY
python harp.py exec runs\SESSION_DIRECTORY "curl -i http://target:8000/"
python harp.py delegate runs\SESSION_DIRECTORY "Inspect the discovered HTTP service" --steps 5
python harp.py finish runs\SESSION_DIRECTORY --success unknown
```

Use the full directory printed by `start` in place of `runs\SESSION_DIRECTORY`. The CLI streams terminal output as commands run. MCP returns each bounded command's output when the tool call finishes.

## Reconnaissance

After a successful scan, HARP stores structured service findings, `.htb` hostnames reported in Nmap XML, and the startup HTTP and SMB probes under `runs/_recon_cache`. A new session reuses them immediately when the target IP, runtime, network route settings, and scan port range match. If the IP changed but the scan environment still matches, HARP checks only ports found in prior runs for a concrete `.htb` hostname. A matching name reuses the earlier port findings and refreshes HTTP and SMB probes against the new IP. If no name matches, HARP performs full reconnaissance. The event stream records the identity check, matched hostname, and source session. Existing completed sessions can seed the cache on first reuse, including hostnames preserved in their Nmap event logs. The cache is separate from individual session logs and persists when a session is deleted; use **Refresh reconnaissance** to replace an entry. Saved findings may be stale if an HTB machine is reset or services change, so refresh when that matters.

When Nmap identifies a Windows SMB service, deterministic reconnaissance also runs NetExec share, user, and RID enumeration with the literal username `.` and an empty password. These three probes run in the selected Kali runtime and appear in the event log and oracle context. NetExec uses lowercase `-u` for the username option.

For VPN targets, the full TCP sweep uses a bounded, moderate packet rate. If it suggests Active Directory but finds fewer than eight ports, HARP waits briefly and performs a slower full-port pass. A short TCP connect scan then checks common AD and WinRM ports before version detection. HARP merges findings from all passes and logs each command. The slower pass adds startup time only when the first result looks incomplete; it still cannot guarantee every high dynamic port will appear in every run.

## Hack The Box through the VPN

Choose **Existing Kali WSL** to use Kali's installed tools and its VPN route, or **Disposable Docker** to use a container behind Docker Desktop's Windows networking. Docker Desktop [documents outbound networking](https://docs.docker.com/desktop/features/networking/) and [VPN behavior](https://docs.docker.com/desktop/features/networking/networking-how-tos/). VPN client settings can block container traffic, so check target reachability through HARP's selected Kali runtime before a real assessment.

1. Connect the authorized Hack The Box VPN on Windows.
2. In the GUI, choose **Use HTB VPN profile**, select the Kali runtime, set the exact authorized target IP, and start a Hybrid session. Docker mode creates `harp_vpn` and builds the Kali image if needed; WSL mode uses the configured distribution and user. A successful scan of the expected target service is the connectivity check. If the scan finds nothing, verify VPN routing and target state before delegating.

In Docker mode, HARP refuses host networking, an internal bridge selected as a VPN bridge, and a VPN bridge already occupied by other containers. In VPN mode, neither Docker nor WSL networking enforces the target IP; the target name, prompts, and experiment procedure define the authorized scope. Use only environments you are authorized to test.

## Activity status and cost display

The event-stream status uses a steady dot and one of three labels:

| Label | Meaning |
| --- | --- |
| LIVE | The selected session is active or running reconnaissance. |
| SAVED SESSION | You are viewing the final state of a finished session. |
| RECORDED REPLAY | You are playing or seeking through saved events, including while paused. |

The dot and label stay steady during dashboard refreshes. The indicator does not blink to imply activity in a saved session.

The **Cache and cost** panel shows oracle and proxy estimates, their combined total, an oracle-only estimate for the same recorded workload, and estimated Hybrid savings in dollars and percent. Prices saved after a run apply on the next refresh when the configured provider and model match. Replay costs follow the playhead. See [late pricing](configuration.md#prices-entered-after-a-session) and [Hybrid cost comparison](configuration.md#hybrid-cost-comparison) for the calculation, unknown-price handling, and assumptions. Historical per-call estimates in the event stream remain as originally recorded.

## Replay a saved session

Select a finished session in the sidebar and click **Replay saved session** in the top bar. Replay loads the saved event log and opens at the beginning, paused. No target commands, model requests, or Kali startup are needed.

- **Play / Pause** controls playback. **Restart** returns to the beginning, paused.
- **Speed** offers 1× through 32× playback. **Shorten idle gaps** compresses long waits to three seconds of session time before the next event. Turn it off for the original pacing.
- Drag the timeline to seek. **Next finding** skips to the next oracle plan, artifact, newly detected flag, or session finish.
- Overview, Verbose, Flags, and Artifacts show only the evidence revealed by the playhead. Rewinding removes later findings from the display. Successful runs end with the green completion dialog.
- **Exit replay** returns to the saved session view. Selecting another session also exits replay.

The sticky playback bar and status badge identify the display as a recorded replay. The elapsed clock shows original session time, including when waits are shortened. Session controls and write requests are disabled during replay. Playback does not acknowledge flags, change the artifact registry, or alter the original outcome or logs.

Replay recognizes terminal-backed flags using the current detector, including NetExec prefixes, so older runs can show flags at their original file-read event even if their registry entries were repaired later. Other artifacts appear at their recorded registration event. Reconstruction stops at the original finish event, excluding later reconciliation annotations. Proxy usage advances on recorded actions and invalid replies using the saved call ledger, while hosted oracle usage follows recorded usage events. If older logs lack events or usage, the replay cannot reconstruct missing details.

For a demonstration video, choose a successful run, start playback with idle-gap shortening enabled, and record the dashboard with your screen recorder. You can switch tabs or pause on evidence while recording.
