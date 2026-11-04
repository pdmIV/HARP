# HARP: WSL backed Kali prototype

This prototype makes **Codex the oracle** and an Unsloth Desktop model the local worker. It does not call an OpenAI API. Codex connects to HARP through the project MCP server and can inspect a session, issue terminal commands, or delegate a bounded objective to the local model. HARP starts with deterministic reconnaissance, turns Nmap XML into a compact service list, and stores the full transcript and Markdown notes for review.

The Linux tools run in a Docker Desktop Linux container on the WSL 2 backend. The target can run Windows or Linux; the Kali image includes Nmap, SMB, LDAP, Impacket, HTTP, DNS, SSH, and related tools. Target commands execute in the container, never through `wsl.exe` in your Kali distribution.

```text
Codex desktop (oracle) ── MCP ── HARP on Windows ── Docker API ── Kali container
                                  │                         │
                                  │                         └── authorized target
                                  └── Unsloth Desktop API (local worker)
```

## Host protection

Each session gets a disposable Kali container. It runs as UID 10001 by default, with a read only root filesystem, small writable `/tmp` and `/workspace` memory filesystems, no Windows drive mount, no Docker socket, no published ports, no privileged mode, a PID limit, a CPU limit, and a 512 MiB memory limit by default. All Linux capabilities are dropped except `NET_RAW`, which is reserved for a separately approved root command. Commands and output are time and size bounded. When the session ends, HARP removes the container and its temporary files.

The local model cannot call Docker or the Windows shell. It can request a root command; HARP stops the delegation and exposes that exact command for human approval. The command center has an approval button for these requests. The `terminal_root` MCP tool is also configured in [`.codex/config.toml`](.codex/config.toml) with `approval_mode = "approve"`; while the command center is open, it requires an additional approval there. A root approval increments `root_approvals`; it does **not** mark human tactical intervention. A manual Kali command entered in the web app does mark tactical intervention. The CLI intentionally refuses `root-exec` so the normal workflow cannot silently bypass the approval path.

Containers are a practical boundary, not a guarantee against a container escape or against reaching Windows network services when using an outbound bridge. Keep Docker Desktop and Windows updated. For stronger host separation, use Docker Desktop Enhanced Container Isolation or a dedicated VM. Do not add host bind mounts, `--privileged`, Docker socket mounts, or host networking to the worker. The provided lab uses an internal bridge with an isolated gateway. The VPN mode uses a separate outbound bridge and therefore relies on the Windows VPN and your host firewall for network routing and scope.

## Setup

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

The Codex chat is the frontier-model oracle; the web command center is the live monitor and approval surface; Unsloth serves the local worker. HARP does not need an OpenAI API key for this route.

1. Start Docker Desktop's Linux engine and connect the authorized Hack The Box VPN on Windows.
2. In the ChatGPT desktop app, open **Codex** on this trusted local project folder and start a new Codex chat. Choose an eligible GPT-6 model and enable or verify Daybreak if your account offers it. Daybreak is an access setting, not necessarily a separate model name. Confirm that the `harp` MCP server is available; `codex mcp list` also reports its configured status. If you just changed `.codex/config.toml`, reopen the project or restart Codex.
3. Tell Codex **"Launch HARP."** It calls `launch_control_center`, which starts or reopens the web command center in your browser. Codex then waits for you to start a Hybrid session in the browser; it does not start a separate run.
4. In **Local model**, enter your Unsloth model ID and context/KV-cache settings, then select **Launch model**. An already running server is reused. HARP captures a generated Unsloth key and encrypts it for your Windows account. If you started Unsloth separately, store its key with `python set_unsloth_key.py`. Keep the key out of chat.
5. In **Configuration**, select **Use HTB VPN profile**, enter the exact authorized target IP, and save. Choose **Hybrid** on Overview and click **Start session**. HARP creates the dedicated VPN bridge and builds the Kali image on first use, then runs deterministic reconnaissance. The new run appears in the session list.
6. Codex's `wait_for_session` tool picks up that run and its reconnaissance. Codex can publish an operator plan, delegate bounded local tasks, inspect terminal evidence, request root approval when needed, capture both flags, and finish the run. Keep the browser open to monitor events and approve commands.

The `.codex/config.toml` in this checkout names `S:\HARP` explicitly. If you clone the repository elsewhere, update its `args` and `cwd` paths to that clone before opening Codex. An ordinary ChatGPT chat without this local Codex workspace and MCP server cannot operate HARP through these tools.

## Web command center

Launch the local web command center from PowerShell:

```powershell
cd S:\HARP
python harp_web.py
```

The launcher opens a browser on `127.0.0.1:8765`. Codex can launch it through `launch_control_center`; the direct Python command remains available. The control API requires a private token held in that browser tab; other pages cannot control HARP merely by reaching localhost. The interface has light and dark themes, responsive layouts, and side navigation for Overview, Flags, Artifacts, Local model, and Configuration.

**Overview** follows each session's event log, showing deterministic recon, explicit oracle plan updates, delegated objectives, local model actions and short stated reasons, terminal output, approvals, and outcomes. It also shows elapsed time, model calls, terminal calls, token usage, and flag progress. Codex's private reasoning is not available to the app; the project MCP tool `record_oracle_plan` publishes a concise operator-facing plan, and [AGENTS.md](AGENTS.md) tells Codex to use it when the strategy changes.

**Flags** shows the actual `user.txt` and `root.txt` values. An alert blinks in the side navigation while a newly captured flag is unseen, and opening Flags acknowledges it. A successful file-reading command that names exactly one flag file and returns a line containing only one 32-character hexadecimal value is captured automatically. When both flags have terminal evidence, HARP timestamps verified success. Other flag formats can be recorded with the evidence-backed `record_artifact` MCP tool.

**Artifacts** shows credentials, document excerpts, flags, and other evidence with source commands. Values are visible in full. The local model may nominate an artifact, but HARP records it only when its exact value appears in terminal or deterministic HTTP probe output. Codex can use `record_artifact` for an evidence-backed item it identifies. For a regular file under Kali `/workspace`, `capture_document` preserves up to 8 MiB without a host mount, records a text preview and SHA-256, and adds a download button to the panel. Binary files are available as downloads and are not rendered inline.

**Local model** configures model ID, API port, context, K/V cache types, parallel slots, thinking mode, and HARP's prompt and reply caps. **Launch model** starts Unsloth with server-side tools disabled. Its generated API key is captured, encrypted for the current Windows account, and redacted from process logs. **Configuration** sets the target, Docker network, scan ports, and Kali limits for new sessions. A changed objective or manually entered Kali command is recorded as human tactical help; approving a pending root command is not.

If a model is already listening on the selected port, the app monitors it without starting another. If Codex requests root while the web app is active, approve the exact command in the Codex prompt and then in the app. If the web app is closed, the Codex approval remains the gate. The app can also approve a local model's pending root request, after which delegation can continue. Stopping the Python web process stops only an Unsloth model it launched itself.

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

## Local worker and context management

The local model receives the target, objective, structured reconnaissance, bounded HTTP probes, the four most recent terminal results, previous command names, and a small set of durable notes. A new API call is made for each step, so the model does not need a growing conversation or KV cache. HARP reads the server's reported context length, counts each request with its token-count endpoint, reserves output space, and trims old excerpts if needed. `local.max_input_tokens` caps the prompt even when the server supports more; the effective cap is also limited by the reported context length. Raw output stays in `events.jsonl`; the model sees capped excerpts. `Field Notes.md` is Obsidian readable and can be opened as a vault or copied into an existing one. The container never mounts the notebook.

The worker may search earlier evidence with a `memory_query` action. Search results distinguish terminal evidence from **unverified model notes**. This is a simple keyword retrieval baseline, useful for testing whether persistent memory helps after context resets; it is not semantic retrieval yet.

HARP stops a delegation on a repeated command, repeated output, three failed or empty commands, repeated or excessive memory searches, two invalid model replies, a root request, or the step budget. Codex can inspect the reason and decide whether to give a narrower task. The global session budget prevents unlimited retries.

## Evaluation protocol

Run the same target snapshot and objective under three modes:

| Mode | Tactical controller | Tool access |
| --- | --- | --- |
| `frontier-only` | Codex | Direct terminal; local delegation disabled |
| `local-only` | Unsloth | Delegation; direct Codex terminal disabled |
| `hybrid` | Codex delegates and reviews | Both |

The deterministic scan is identical in all modes. Fix the time limit, command limit, model quantization, context budget, and starting target state before comparing runs. Repeat each target and mode, and record target OS, difficulty, and a predeclared success criterion. Verify success outside the model's self report, then call `mark_success` immediately with a short evidence description or a hash. `finish_session` stops the clock and removes Kali. `mark_human_intervention` is for tactical hints only; approving a root command does not trigger it.

Each session stores elapsed time, time to verified success, success before human tactical intervention, local input and output tokens reported by Unsloth, model latency, local step count, oracle action count, root approval count, and sampled Kali memory. `python harp.py report` prints one JSON record per run. Codex plan token usage is left **unknown** unless you enter a trustworthy count with `record_oracle_usage`; HARP cannot infer plan usage or a marginal subscription price from its tool calls. The local model's token usage is marked incomplete if Unsloth omits usage fields. Sampled Kali memory does not include Unsloth's RAM or VRAM; record those separately for the final report.

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
