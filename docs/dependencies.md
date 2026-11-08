# Install dependencies

Kali WSL is the primary Windows setup. For native Kali, run setup as your ordinary user from a Kali terminal:

```bash
sudo -v
python3 scripts/install_dependencies.py --runtime native
python3 scripts/install_dependencies.py --runtime native --check
```

Native setup elevates only apt with noninteractive sudo, then installs pipx tools as the current user. Open a new login shell afterward. The dashboard can run offline checks; use the terminal installer when sudo authentication is needed. No hypervisor-specific configuration is required. See [native Kali setup](setup.md#native-kali-linux).

The web command center checks the saved Kali runtime in the background. If tools
are missing, incompatible, or the runtime cannot be reached, click the dependency
warning to open a centered setup pane. Review its distribution/user or Docker
image, then click **Install dependencies**. The pane shows live output and a green
success message only after installation and offline checks pass. Click **Done**
to close it. It stays closed on subsequent dashboard refreshes.

Use **Recheck** after installing tools outside HARP. Checks are cached for five
minutes and do not contact lab targets or download Docker images. Save runtime
changes in Configuration before opening setup. Installation is unavailable while
a session is active, and new sessions cannot start during installation. Errors
remain visible with the installer output so you can resolve them and retry.

Run these commands from the HARP repository root in PowerShell, before starting
a lab session. Install Python 3.10 or newer on Windows and prepare your chosen
Kali runtime first. HARP's host Python needs no pip packages.

## Existing Kali WSL

Use the exact distribution and nonroot user you will select in HARP:

```powershell
python scripts/install_dependencies.py --runtime wsl --distro kali-linux --user kali
```

Replace both names if your installation differs. The wrapper installs apt
packages as root in that distribution, then installs Python tools with pipx as
the selected user. It does not change the default distribution or install tools
on Windows. It adds `~/.local/bin` to that user's `.profile`, which HARP's login
shell reads. No root password prompt is needed through the WSL wrapper.

## Disposable Docker runtime

Start Docker Desktop with its Linux engine, then build the tool image:

```powershell
python scripts/install_dependencies.py --runtime docker
```

The Dockerfile uses the same installer. Isolated environments live under
`/opt/harp/pipx` with executable links under `/usr/local/bin`, available to HARP's
nonroot container user. `--image TAG` selects another build tag; HARP uses
`harp-kali:latest` by default. The existing direct Docker build command also
installs these dependencies.
The wrapper rebuilds without cached install layers so rerunning picks up updates,
then verifies the image as its nonroot user with networking disabled.

## Included tools

| Tools | Purpose |
| --- | --- |
| Whippet with its `analysis` extra | AD graph queries, batch protocol, NetworkX ranked paths |
| `bloodhound-ce` | BloodHound-compatible collection through `bloodhound-ce-python` |
| `certipy-ad` | AD CS collection/assessment through `certipy` |
| Nmap, NetExec, Impacket, SMB/LDAP/DNS tools, enum4linux-ng, Evil-WinRM | Reconnaissance and Windows/AD lab work |
| curl, WhatWeb, Gobuster, SSH, netcat, coreutils | Existing service/terminal workflows |
| Python, venv, pipx, Git, certificates | Isolated tool installation |

Whippet, BloodHound CE's collector and Certipy have separate pipx environments.
They are not imported into HARP's Python environment. Installation needs Internet
access to Kali repositories, GitHub and Python package indexes. Re-running
updates/reinstalls Whippet without touching HARP session data. An existing
`bloodhound-ce-python` or `bloodhound-python` collector and an existing
`certipy-ad` or `certipy` executable are reused. Missing collectors are installed
through pipx. The checks and models receive the detected executable names.

`bloodhound-python` is the legacy collector, with its own flags and output
coverage. It is accepted for Whippet-compatible legacy collection rather than
treated as the CE executable. `certipy-ad` is preferred when both Certipy command
names are present. `enum4linux` is a different legacy tool; the installer still
provides and checks `enum4linux-ng` separately.
The oracle, proxy and Codex guidance explicitly prefer `enum4linux-ng` whenever
available, even when both tools are installed. Legacy `enum4linux` is a fallback
for missing NG or an observed limitation, with the reason stated. This preference
does not cause HARP to repeat completed reconnaissance.

Whippet defaults to its `main` branch. Select a reviewed commit/tag for repeatable
experiments:

```powershell
python scripts/install_dependencies.py --runtime wsl --distro kali-linux --user kali --whippet-ref COMMIT_OR_TAG
```

Docker accepts the same option. Apt and other Python dependencies track their
repositories/indexes; this is not a fully locked environment.

## Offline verification

Both installation paths finish with checks for required executables, a synthetic
Whippet batch handshake/query, a NetworkX ranked-path query, and collector help
commands. No lab target is contacted. Verify again without installing/downloading:

```powershell
python scripts/install_dependencies.py --runtime wsl --distro kali-linux --user kali --check
python scripts/install_dependencies.py --runtime docker --check
```

Docker checking starts a temporary container with networking disabled. For direct
use inside Kali, run `bash scripts/install-dependencies.sh` as the configured
session user. It uses sudo only for apt. Add `--check` for offline verification.

The scripts do not provision WSL, Docker Desktop, a VPN, API keys, or Unsloth.
Restart HARP after installation and select the same runtime/distribution/user.
An existing WSL pipx installation is not available inside Docker.
