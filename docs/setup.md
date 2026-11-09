# Setup

For installation without a checkout, see [package installation](packaging.md).
The installed `harp-ai` command launches the dashboard from any directory;
`harp-ai deps` runs the same dependency setup described below.

[Home](../README.md) · [Setup](setup.md) · [Configuration](configuration.md) · [Running sessions](running-sessions.md) · [Host protection](host-protection.md) · [Evaluation](evaluation.md)

Kali WSL is the primary Windows setup. Native Kali Linux is also supported, whether installed on hardware or in VMware, VirtualBox, or another VM. Docker remains optional. HARP uses Python's standard library. Hosted models do not require Unsloth or a local GPU. Existing saved configurations keep their selected runtime; a fresh dashboard defaults to WSL on Windows and native Kali on Linux.

## Existing Kali WSL

First run the [dependency installer](dependencies.md) for your selected runtime.
It installs Whippet with NetworkX, BloodHound CE's collector, Certipy, and the
existing Kali tools, then verifies them offline. For example, from PowerShell:

```powershell
python scripts/install_dependencies.py --runtime wsl --distro kali-linux --user kali
```

Replace the distribution and user with the exact values configured below.

For the existing Kali WSL runtime, select **Existing Kali WSL** in Configuration, set the distribution and user (default `kali-linux` and `kali`), and use the VPN network policy. HARP checks for `nmap`, `nxc`, `timeout`, and `python3` before starting. The Docker network, memory, and CPU settings are ignored in WSL mode. HARP uses TCP connect scans there so nonroot Kali can perform deterministic reconnaissance. Document capture accepts files in the session workspace shown in the session record.

## Native Kali Linux

Run HARP inside Kali as your ordinary nonroot user. Clone the repository there, then run these commands from its root:

```bash
sudo -v
python3 scripts/install_dependencies.py --runtime native
python3 scripts/install_dependencies.py --runtime native --check
python3 harp_web.py
```

The terminal installer elevates only the apt stage with `sudo -n`; Python tools are installed with pipx as your current user. The dashboard's **Install dependencies** button uses Kali's system authentication dialog for apt instead. Enter your administrator password in that system dialog; HARP never asks for it in the web page. If a system dialog is unavailable, run setup from your Kali terminal as shown above. Open a new login shell after installation so pipx tools are on PATH.

Select **Native Kali Linux**, the **VPN / direct Kali network** policy, and the exact authorized target IP. A fresh Linux dashboard already selects this runtime. For headless configuration, copy `harp.native.example.json` to `harp.json`, replace the target placeholder, and configure your models. The original `harp.example.json` is still the optional Docker demo configuration.

Connect the HTB VPN inside Kali, or supply another working route from Kali to the target. HARP does not configure a hypervisor, VM adapter, or VPN. Run the browser and MCP server inside the same Kali environment. For Codex MCP, use `python3` and the absolute Linux path to `harp_mcp.py`; Windows executable paths do not apply. Keep the dashboard bound to loopback.

Commands run in `~/.local/share/harp/runs/<runtime-session>/`. Images, documents, Whippet captures, and managed batch queries use that workspace. HARP logs commands through the same terminal interface, uses nonroot Nmap TCP connect scans, and preserves files when the session finishes. Native mode does not create containers, invoke WSL, or delete your VM.

Root commands still require the exact-command HARP approvals. Approved native commands use `sudo -n` and fail if local sudo authorization is unavailable. HARP never prompts for, stores, or pipes your sudo password. Do not launch the whole application with sudo. Native mode runs with your user's host permissions, not a filesystem sandbox, so use a dedicated lab VM where appropriate.

API keys can be imported in the dashboard or provided as environment variables. Windows imports use DPAPI. On Linux, imports are stored unencrypted in owner-only mode-600 files under a mode-700 `.secrets` directory. Windows encrypted key files cannot be transferred to Linux; reimport them. Session evidence may contain recovered secrets, so protect the repository and session workspace as well.

## Docker and the local demo

The following Docker setup is optional when using WSL:

1. Start Docker Desktop with its Linux engine and WSL 2 backend.
2. Build the Kali tool image, including Whippet and its AD companion tools:

   ```powershell
   docker build -f Dockerfile.kali -t harp-kali:latest .
   ```

3. Copy [harp.example.json](../harp.example.json) to `harp.json`. Configure hosted providers using the [configuration guide](configuration.md), or set the exact model ID exposed by Unsloth Desktop for a local proxy. The model API URL defaults to `http://127.0.0.1:8888/v1`; change the port if your installation uses another loopback port. In the command center, open **API Keys**, select Unsloth, paste its key, and click **Import API key**. The key under `.secrets` is encrypted for your Windows account and ignored by Git. For headless use, set `UNSLOTH_API_KEY` in the environment of the process running HARP. HARP reads it on demand, so Codex does not need a restart for the key.
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

## Launch the command center

```powershell
python harp_web.py
```

Import credentials in **API Keys**, choose the planner in **Oracle model**, configure the worker in **Proxy model**, and set the runtime and authorized target in **Configuration**. See [running sessions](running-sessions.md) for the first run.

## References

- [Docker Desktop WSL 2 backend](https://docs.docker.com/desktop/features/wsl/)
- [Docker network isolation and gateway mode](https://docs.docker.com/reference/cli/docker/network/create/)
- [Docker resource limits](https://docs.docker.com/engine/containers/resource_constraints/)
- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp)
- [Unsloth Desktop API endpoint](https://unsloth.ai/docs/basics/api)
