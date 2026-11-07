# HARP: WSL backed Kali prototype
<p align="center">
  <img src="assets/harp-banner.png"
       alt="HARP — Hierarchical AI-Agent Penetration Testing"
       width="100%">
</p>

HARP supports **OpenAI API**, **NVIDIA NIM**, or Codex as the Hybrid oracle, with OpenAI API, NVIDIA NIM, or Unsloth Desktop as the proxy model. The selected oracle reviews deterministic reconnaissance, plans bounded delegations, and relies on terminal evidence for flags. HARP stores the full transcript and Markdown notes for review.

When Nmap identifies a Windows SMB service, deterministic reconnaissance also runs NetExec share, user, and RID enumeration with the literal username `.` and an empty password. These three probes run in the selected Kali runtime and appear in the event log and oracle context. NetExec uses lowercase `-u` for the username option.

For VPN targets, the full TCP sweep uses a bounded, moderate packet rate. If it suggests Active Directory but finds fewer than eight ports, HARP waits briefly and performs a slower full-port pass. A short TCP connect scan then checks common AD and WinRM ports before version detection. HARP merges findings from all passes and logs each command. The slower pass adds startup time only when the first result looks incomplete; it still cannot guarantee every high dynamic port will appear in every run.

### NVIDIA NIM oracle

In **Configuration**, choose **NVIDIA NIM API**, load and select a chat model from the dropdown, and save your API key with **Save API key**. The key is encrypted for the current Windows account under `.secrets`; alternatively set `NVIDIA_API_KEY` in the HARP process environment. **Find available models** requests IDs from NVIDIA's model API and populates the model dropdown. See [NVIDIA's API catalog](https://build.nvidia.com/explore/discover) for model details. Model listing does not establish access or free usage for an individual key.

In **Proxy model**, choose **NVIDIA NIM API**, load models, and select a separate proxy model. The oracle and proxy can both use NIM, with independent model choices and the same saved API key. HARP sends each proxy step to NIM's chat API, then validates and runs any requested command through the selected Kali terminal. No Unsloth server is required for this pairing.

For `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`, the proxy's **Enable thinking mode** setting controls whether HARP requests reasoning or instruct mode. Reasoning requires at least 4,096 reply tokens; selecting it in the command center raises a lower cap to 8,192. Empty proxy replies receive one bounded retry. Repeated empty or malformed replies stop the delegation for oracle review. Three oracle delegations without a new terminal result stop the NIM loop for operator review, even when budgets are removed.

**Compare oracle models** tests up to five IDs with one small, synthetic HARP planning prompt per model (at most three requests at once), ranks valid JSON plans by response time, and lets you save a tested model. It sends no target reconnaissance. A single sample indicates current responsiveness, not long-run stability or the latency of a full target-specific plan; rerun before a session if provider load changes. HARP does not continuously ping models or automatically switch oracle models mid-session.

Start a Hybrid session in the command center. After deterministic reconnaissance, HARP runs the selected NIM oracle for at most `oracle.max_cycles` cycles, delegating at most `oracle.steps_per_cycle` proxy steps each time. After failed or repetitive proxy commands, invalid replies, or null SMB access denial, the oracle reviews the evidence and may issue a corrected delegation or one validated, read-only probe. Recovery cycles share the regular `oracle.max_cycles` session limit and have no separate cap. A rejected probe returns its validation reason to NIM for correction instead of ending the loop. If an active NIM session stops, **Resume oracle** continues its remaining cycle budget without repeating deterministic reconnaissance. Root requests, operator stops, exhausted budgets, and model API errors still stop the loop. The oracle never runs target commands outside the HARP terminal. Verified flag capture ends the session. The Codex MCP workflow remains available by selecting **Codex via MCP**.

For prototype runs, **Remove hosted oracle cycle and proxy step/model-call budgets** in Configuration applies to new Hybrid sessions. The same choice on Overview applies when resuming the selected active NIM session, including one that has reached its old cycle limit. Repetition, failed-command, invalid-reply, root-approval, and operator-stop checks remain in effect. The oracle reconsiders new evidence each cycle; evidence-backed credentials are included in its compact context. A discovered password is not assumed to belong to a particular user until a login confirms it, and a confirmed account prompts renewed enumeration before a later path is chosen.

The command center logs **NIM planning** as soon as the oracle request starts and records response time when it returns. Mistral Large 4 can take well over a minute to produce a plan even with a compact prompt; HARP allows up to four minutes for its chat response. Docker mode rebuilds its Kali image only when its Dockerfile changes or the image is missing. WSL mode uses the installed Kali tools directly.

Choose **Existing Kali WSL** in Configuration to use your installed `kali-linux` tools, including `crackmapexec` and `nxc`. HARP runs commands through its logged terminal interface as the configured Kali user. Docker remains available for disposable sessions. Existing sessions keep their original runtime.

```text
Codex desktop (oracle) ── MCP ── HARP on Windows ── WSL Kali or Docker Kali
                                  │                         │
                                  │                         └── authorized target
                                  └── Unsloth Desktop or NVIDIA NIM API (proxy model)
```

## Host protection

In Docker mode, each session gets a disposable Kali container. It runs as UID 10001 by default, with a read only root filesystem, small writable `/tmp` and `/workspace` memory filesystems, no Windows drive mount, no Docker socket, no published ports, no privileged mode, a PID limit, a CPU limit, and a 512 MiB memory limit by default. All Linux capabilities are dropped except `NET_RAW`, which is reserved for a separately approved root command. Commands and output are time and size bounded. When the session ends, HARP removes the container and its temporary files.

The proxy model cannot call Docker or the Windows shell. It can request a root command; HARP stops the delegation and exposes that exact command for human approval. The command center has an approval button for these requests. The `terminal_root` MCP tool is also configured in [`.codex/config.toml`](.codex/config.toml) with `approval_mode = "approve"`; while the command center is open, it requires an additional approval there. A root approval increments `root_approvals`; it does **not** mark human tactical intervention. A manual Kali command entered in the web app does mark tactical intervention. The CLI intentionally refuses `root-exec` so the normal workflow cannot silently bypass the approval path.

Before a delegated command executes, HARP checks shell syntax inside Kali and applies inexpensive plan-scope checks for the authorized IP and any SMB share named in the oracle objective. It also rejects interactive `smbclient mget` without `prompt off`, a known filename-quoting mistake, named accounts in null-auth tasks, and SMB passwords that have no terminal evidence. A null-auth access denial immediately returns control to the oracle for replanning. Rejections return a concrete correction to the proxy model and appear in the event log; three rejected commands stop the delegation. These checks do not prove that every action advances the plan, so the oracle still reviews the terminal evidence after each bounded delegation. Identical duplicate JSON actions are accepted; after a malformed reply HARP retries at lower temperature and, for Unsloth, with thinking disabled.

The WSL runtime uses your existing distribution, whose Windows mounts and home files are accessible to Kali commands. It does not provide the Docker container isolation or resource limits. HARP uses a per-session directory under `/home/<user>/.local/share/harp/runs/`, but that directory is not a security boundary. Use WSL mode only for trusted proxy models and authorized targets. HARP leaves the WSL workspace on disk after a session; remove it yourself after preserving evidence.

Containers are a practical boundary, not a guarantee against a container escape or against reaching Windows network services when using an outbound bridge. Keep Docker Desktop and Windows updated. For stronger host separation, use Docker Desktop Enhanced Container Isolation or a dedicated VM. Do not add host bind mounts, `--privileged`, Docker socket mounts, or host networking to the worker. The provided lab uses an internal bridge with an isolated gateway. The VPN mode uses a separate outbound bridge and therefore relies on the Windows VPN and your host firewall for network routing and scope.

## Setup

For the existing Kali WSL runtime, select **Existing Kali WSL** in Configuration, set the distribution and user (default `kali-linux` and `kali`), and use the VPN network policy. HARP checks for `nmap`, `nxc`, `timeout`, and `python3` before starting. The Docker network, memory, and CPU settings are ignored in WSL mode. HARP uses TCP connect scans there so nonroot Kali can perform deterministic reconnaissance. Document capture accepts files in the session workspace shown in the session record.

The following Docker setup is optional when using WSL:

1. Start Docker Desktop with its Linux engine and WSL 2 backend.
2. Build the Kali tool image:

   ```powershell
   docker build -f Dockerfile.kali -t harp-kali:latest .
   ```

3. Copy [harp.example.json](harp.example.json) to `harp.json`. Set the exact model ID exposed by Unsloth Desktop. The model API URL defaults to `http://127.0.0.1:8888/v1`; change the port if your installation uses another loopback port. In your own PowerShell window, run `python S:\HARP\set_unsloth_key.py` and paste the Unsloth key when prompted. Input is hidden; the file under `.secrets` is encrypted for your Windows account and ignored by Git. HARP reads it on demand, so Codex does not need a restart for the key. You may instead provide `UNSLOTH_API_KEY` to the Codex environment.
   For a GGUF model, an explicit 32K context with a BF16 KV cache can be launched with:

   ```powershell
   unsloth studio run --model 'HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive:Q4_K_P' --port 8888 --disable-tools --parallel 1 --max-seq-length 32768 --cache-type-k bf16 --cache-type-v bf16
   ```

   Change `32768` to `131072` for a 128K context if memory permits. `bf16` uses 16 bits per KV element, so it does not lower KV memory compared with `f16`. To reduce KV memory, try `q8_0` for both cache types and verify output quality on the lab tasks. Unsloth may cap automatic context sizing to fit GPU memory; HARP records the context the running server actually reports. The configured `max_input_tokens` is a prompt cap, not a request to fill the whole context.
4. For the local demo, start the sample target and its closed network:

   ```powershell
   docker compose up -d --build
   python harp.py doctor
   ```

5. Restart Codex in this workspace to load the project MCP configuration. `codex mcp get harp` shows whether the server is enabled. The MCP adapter uses only Python's standard library.

Codex can then call `launch_control_center`, `wait_for_session`, `inspect_session`, `terminal`, `delegate_local`, `mark_success`, and `finish_session`. `start_session` remains available for an explicitly requested headless run.

## Start a hybrid run with Codex

The Codex chat is the frontier-model oracle; the web command center is the live monitor and approval surface; Unsloth or NIM serves the proxy model. HARP does not need an OpenAI API key for this route.

1. Start Docker Desktop's Linux engine and connect the authorized Hack The Box VPN on Windows.
2. In the ChatGPT desktop app, open **Codex** on this trusted local project folder and start a new Codex chat. Choose an eligible GPT-6 model and enable or verify Daybreak if your account offers it. Daybreak is an access setting, not necessarily a separate model name. Confirm that the `harp` MCP server is available; `codex mcp list` also reports its configured status. If you just changed `.codex/config.toml`, reopen the project or restart Codex.
3. Tell Codex **"Launch HARP."** It calls `launch_control_center`, which starts or reopens the web command center in your browser. Codex then waits for you to start a Hybrid session in the browser; it does not start a separate run.
4. In **Proxy model**, choose Unsloth or NIM. For Unsloth, enter its model ID and context/KV-cache settings, then select **Launch model**. An already running server is reused. HARP captures a generated Unsloth key and encrypts it for your Windows account. If you started Unsloth separately, store its key with `python set_unsloth_key.py`. For NIM, enter its model ID and save the NVIDIA key in Configuration. Keep keys out of chat.
5. In **Configuration**, select **Use HTB VPN profile**, enter the exact authorized target IP, and save. Choose **Hybrid** on Overview and click **Start session**. HARP creates the dedicated VPN bridge, refreshes the cached Kali image, runs a full TCP SYN port sweep (`-Pn -T4 --min-rate 10000 --open -p-`), then runs lightweight version detection only on open ports. No proxy-model request happens before this reconnaissance. The new run appears in the session list.
6. Codex's `wait_for_session` tool picks up that run and its reconnaissance. Codex publishes a concise operator plan, delegates one bounded task at a time, reviews the resulting evidence and stop reason, then plans the next task until the flags are verified or a stopping condition is reached. Keep the browser open to monitor events and approve commands.

The Codex heartbeat named **HARP Hybrid oracle loop** checks this chat every minute while active. It resumes the oracle review and delegation cycle without another click in the command center. It stays quiet when no Hybrid session is active or a delegation is still running. The optional **Unbridled** checkbox removes local step, model-call, duplicate-command, repeated-output, and unproductive-command stops for a delegation. The operator stop control, root approval flow, invalid-reply handling, and evidence checks still apply.

The `.codex/config.toml` in this checkout names `S:\HARP` explicitly. If you clone the repository elsewhere, update its `args` and `cwd` paths to that clone before opening Codex. An ordinary ChatGPT chat without this local Codex workspace and MCP server cannot operate HARP through these tools.

## Web command center

Launch the local web command center from PowerShell:

```powershell
cd S:\HARP
python harp_web.py
```

The launcher opens a browser on `127.0.0.1:8765`. Codex can launch it through `launch_control_center`; the direct Python command remains available. The control API requires a private token held in that browser tab; other pages cannot control HARP merely by reaching localhost. The interface has light and dark themes, responsive layouts, and side navigation for Overview, Flags, Artifacts, Proxy model, and Configuration.

**Overview** follows each session's event log, showing deterministic recon, explicit oracle plan updates, delegated objectives, proxy model actions and short stated reasons, terminal output, approvals, and outcomes. It also shows elapsed time, model calls, terminal calls, token usage, and flag progress. Codex's private reasoning is not available to the app; the project MCP tool `record_oracle_plan` publishes a concise operator-facing plan, and [AGENTS.md](AGENTS.md) tells Codex to use it when the strategy changes.

The **Stop session** button ends an active run and removes its Kali container in Docker mode after any in-flight delegation stops. Finished sessions can be deleted from the Outcome card; deletion permanently removes the session record, logs, artifacts, and captured files. The configured proxy step limit applies to each delegation from an oracle plan unless unlimited budget is selected. Cumulative proxy steps and model calls remain session statistics.

**Flags** shows the actual `user.txt` and `root.txt` values. An alert blinks in the side navigation while a newly captured flag is unseen, and opening Flags acknowledges it. A successful file-reading command that names exactly one flag file and returns a line containing only one 32-character hexadecimal value is captured automatically. When both flags have terminal evidence, HARP timestamps verified success. Other flag formats can be recorded with the evidence-backed `record_artifact` MCP tool.

**Artifacts** shows credentials, document excerpts, flags, and other evidence with source commands. Values are visible in full. The proxy model may nominate an artifact, but HARP records it only when its exact value appears in terminal or deterministic HTTP probe output. Codex can use `record_artifact` for an evidence-backed item it identifies. For a regular file under Kali `/workspace`, `capture_document` preserves up to 8 MiB without a host mount, records a text preview and SHA-256, and adds a download button to the panel. Binary files are available as downloads and are not rendered inline.

**Proxy model** selects Unsloth or NIM and sets HARP's prompt and reply caps. Unsloth settings include API port, context, K/V cache types, parallel slots, and thinking mode. **Launch model** starts Unsloth with server-side tools disabled. Its generated API key is captured, encrypted for the current Windows account, and redacted from process logs. **Configuration** sets the target, Docker network, scan ports, and Kali limits for new sessions. A changed objective or manually entered Kali command is recorded as human tactical help; approving a pending root command is not.

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

## Hack The Box through Windows OpenVPN

Docker Desktop [routes outbound container traffic through its Windows backend](https://docs.docker.com/desktop/features/networking/), and [documents VPN support](https://docs.docker.com/desktop/features/networking/networking-how-tos/). Starting OpenVPN on Windows is the simplest route here because the worker remains an ordinary, unprivileged Linux container. VPN client settings can still block Docker traffic, so check target reachability from **inside** the container before a real assessment.

1. Connect the authorized Hack The Box VPN on Windows.
2. In the GUI, choose **Use HTB VPN profile**, set the exact authorized target IP, and start a Hybrid session. HARP creates `harp_vpn` and builds the Kali image if needed. A successful scan of the expected target service is the connectivity check. If the scan finds nothing, verify VPN routing and target state before delegating.

HARP refuses host networking, an internal bridge selected as a VPN bridge, and a VPN bridge already occupied by other containers. In VPN mode, Docker networking does not enforce the target IP; the target name, prompts, and experiment procedure define the authorized scope. Use only environments you are authorized to test.

## Proxy model and context management

The proxy model receives the target, objective, structured reconnaissance, bounded HTTP probes, the four most recent terminal results, previous command names, and a small set of durable notes. A new API call is made for each step, so the model does not need a growing conversation or KV cache. For Unsloth, HARP reads the server's reported context length and counts each request with its token-count endpoint. NIM does not expose those endpoints, so HARP uses the configured input cap and a conservative token estimate. Both paths reserve output space and trim old excerpts if needed. `local.max_input_tokens` caps the prompt. Raw output stays in `events.jsonl`; the model sees capped excerpts. `Field Notes.md` is Obsidian readable and can be opened as a vault or copied into an existing one. The container never mounts the notebook.

The worker may search earlier evidence with a `memory_query` action. Search results distinguish terminal evidence from **unverified model notes**. This is a simple keyword retrieval baseline, useful for testing whether persistent memory helps after context resets; it is not semantic retrieval yet.

For the NIM oracle, each request rebuilds context from the session log. It includes the structured startup reconnaissance, four recent terminal results, up to eight distinct older successful results, eight recent plan/delegation outcomes (including terminal failures and command rejection feedback), and eight evidence-backed artifacts. Older output is excerpted and the full log stays on disk. The plan history is a record of attempted approaches, while terminal results and verified artifacts are the evidence for deciding what to do next. This bounded context also survives an oracle restart or resume.

HARP stops a delegation on a repeated command, repeated output, three failed or empty commands, repeated or excessive memory searches, two invalid model replies, a root request, or the step budget. Codex can inspect the reason and decide whether to give a narrower task. The global session budget prevents unlimited retries.

## Evaluation protocol

Run the same target snapshot and objective under three modes:

| Mode | Tactical controller | Tool access |
| --- | --- | --- |
| `frontier-only` | Codex | Direct terminal; local delegation disabled |
| `local-only` | Selected proxy model | Delegation; direct Codex terminal disabled |
| `hybrid` | Codex delegates and reviews | Both |

The deterministic scan is identical in all modes. Fix the time limit, command limit, model quantization, context budget, and starting target state before comparing runs. Repeat each target and mode, and record target OS, difficulty, and a predeclared success criterion. Verify success outside the model's self report, then call `mark_success` immediately with a short evidence description or a hash. `finish_session` stops the clock and removes Kali. `mark_human_intervention` is for tactical hints only; approving a root command does not trigger it.

The Kali worker stays nonroot and drops all Linux capabilities except `NET_RAW`. Nmap receives that capability through its file capability so SYN scans work without running the worker as root. The worker image is rebuilt from the local Dockerfile at session start so permission and scanner changes take effect on existing installations.

Each session stores elapsed time, time to verified success, success before human tactical intervention, proxy input and output tokens reported by the selected provider, model latency, proxy step count, oracle action count, root approval count, and sampled Kali memory. `python harp.py report` prints one JSON record per run. Codex plan token usage is left **unknown** unless you enter a trustworthy count with `record_oracle_usage`; HARP cannot infer plan usage or a marginal subscription price from its tool calls. Proxy token usage is marked incomplete if the selected provider omits usage fields. Sampled Kali memory does not include an Unsloth server's RAM or VRAM; record those separately for the final report.

## Current limits

- The demo target is a harmless HTTP service, not a penetration testing benchmark. Windows target support comes from the general terminal and included protocol tools; it has not been validated against a Windows lab machine yet.
- Root command approval depends on the Codex MCP tool policy loading in the Codex session. Inspect the approval prompt before using it. HARP's CLI refuses root commands.
- Obsidian integration is Markdown export plus bounded keyword retrieval. A full retrieval study and automatic vault synchronization are future experiments.
- There is no automatic Codex plan token or local GPU power measurement. Those fields must come from external measurements.

## References

- [Docker Desktop WSL 2 backend](https://docs.docker.com/desktop/features/wsl/)
- [Docker network isolation and gateway mode](https://docs.docker.com/reference/cli/docker/network/create/)
- [Docker resource limits](https://docs.docker.com/engine/containers/resource_constraints/)
- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp)
- [Unsloth Desktop API endpoint](https://unsloth.ai/docs/basics/api)


### OpenAI API and Daybreak Blue

In Configuration, paste an OpenAI project API key or select a text file containing only the key, then click **Import API key**. HARP encrypts the key with Windows DPAPI under `.secrets/openai.key`. It is never included in `harp.json` or session snapshots. `OPENAI_API_KEY`, if set, takes precedence over the imported key.

Choose **OpenAI API / Daybreak Blue** for the oracle in Configuration, the proxy on the Proxy model page, or both. Set the HTTPS API base URL (default `https://api.openai.com/v1`), click **Load available models** or **Load proxy models**, choose from the dropdown, and save configuration. Each role has its own model, endpoint, and access program. Choose **Standard** when Daybreak is not required.

OpenAI requests use `/responses` with `access_programs.cyber: "daybreak_blue"`, `store: false`, and no provider-side execution tools. Daybreak requires an approved API project and model access. Model discovery lists IDs visible to the key, including models that may not support Responses or Daybreak. It does not prove Daybreak eligibility. See [OpenAI's Daybreak guide](https://developers.openai.com/api/docs/guides/daybreak).

For headless configuration, set either `oracle` or `local` to provider `openai`, with `model`, `base_url`, and `access_program` (`daybreak_blue` or `standard`). Existing token and cycle budgets still apply. Allow enough reply tokens for reasoning plus the visible JSON reply (4096 is a useful starting point). Hosted input token counts are estimates. OpenAI ignores the Unsloth/NIM temperature and thinking controls; model defaults apply.


### Prompt caching and cost accounting

OpenAI oracle and proxy requests place fixed instructions and deterministic reconnaissance before changing objectives, feedback, and terminal observations. Evidence stays in user messages. Serialization and hashed cache routing keys remain stable as working context changes; oracle and proxy use separate keys. No dummy tokens or cache warmup requests are added.

For GPT-5.6 and later GPT families, HARP uses an explicit breakpoint after the stable prefix and explicit-only caching, so changing observations are not written to cache. The default cache lifetime is 30 minutes; each role can select 12 hours in the application. Older models use their native automatic caching without unsupported breakpoint or TTL parameters. Unknown/custom model IDs also use native defaults. Prefix length and model/API eligibility still determine whether caching occurs. OpenAI-compatible third-party endpoints must support these OpenAI parameters for recognized GPT models.

The dashboard and session logs report cached input tokens and cache-write tokens separately. Enter each role's ordinary-input, cached-input, cache-write, and output prices in USD per million tokens. Cache-write prices are the total write rate, not an additional surcharge. Missing prices for used token categories produce an unknown estimate, not zero. For legacy models that do not report cache writes, that category is zero. Estimates are before credits, discounts, or complimentary daily allowances and are not a billing statement. Update rates when switching models or cache lifetime. HARP does not infer free-token eligibility or organization-wide quota remaining from individual responses.

Context compaction still applies and can change a prefix. Caching does not retain omitted proxy history, expand the context window, or change HARP's target scope and command approvals.


OpenAI access errors are terminal for the current oracle operation; HARP does not silently change the selected access program or retry a rejected request. An `access_program_not_enabled` error requires checking API organization/project provisioning. Selecting Standard retains standard API policies and does not guarantee acceptance of a cybersecurity workflow. Error reporting preserves bounded error codes, parameter paths, and request IDs while withholding raw provider messages and response bodies. Live Daybreak eligibility and cache savings must be verified with the operator's own project; automated transport tests use mocked API responses.
