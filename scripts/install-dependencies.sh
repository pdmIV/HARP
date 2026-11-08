#!/usr/bin/env bash
# Run before a HARP session, in Kali. Windows users should use the Python wrapper.
set -euo pipefail

system_install=false
check_only=false
apt_only=false
python_only=false
whippet_ref=main
while (($#)); do
    case "$1" in
        --system) system_install=true ;;
        --check) check_only=true ;;
        --apt-only) apt_only=true ;;
        --python-only) python_only=true ;;
        --whippet-ref)
            if (($# < 2)); then echo '--whippet-ref needs a Git ref' >&2; exit 2; fi
            whippet_ref=$2; shift ;;
        -h|--help)
            echo 'Usage: bash scripts/install-dependencies.sh [--check] [--whippet-ref REF]'
            echo 'Run as the Kali session user; sudo is used only for apt.'
            echo '--system is for root-owned Docker image provisioning.'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
if [[ ! $whippet_ref =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || ((${#whippet_ref} > 200)); then
    echo 'Invalid Whippet Git ref' >&2; exit 2
fi
if $apt_only && $python_only; then echo 'Conflicting install stages' >&2; exit 2; fi

if $system_install; then
    export PIPX_HOME=/opt/harp/pipx
    export PIPX_BIN_DIR=/usr/local/bin
else
    export PATH="$HOME/.local/bin:$PATH"
fi

if ! $check_only; then
    if ((EUID == 0)) && ! $system_install && ! $apt_only; then
        echo 'Run as the configured Kali user, or use --system for a Docker image.' >&2
        exit 2
    fi
    if ! $python_only; then
        if ! command -v apt-get >/dev/null; then echo 'This installer requires Kali/Debian apt.' >&2; exit 2; fi
        elevate=()
        if ((EUID != 0)); then elevate=(sudo); fi
        "${elevate[@]}" apt-get update </dev/null
        "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            nmap libcap2-bin curl ca-certificates dnsutils iproute2 netcat-openbsd \
            smbclient ldap-utils enum4linux-ng python3-impacket evil-winrm netexec \
            whatweb gobuster openssh-client coreutils git python3 python3-venv pipx </dev/null
    fi
    if $apt_only; then exit 0; fi
    export PIP_NO_INPUT=1
    export GIT_TERMINAL_PROMPT=0
    # Isolated environments avoid mixing collector/authentication dependencies.
    pipx install --force "whippet-ad[analysis] @ git+https://github.com/pdmIV/Whippet.git@${whippet_ref}" </dev/null
    if command -v bloodhound-ce-python >/dev/null || command -v bloodhound-python >/dev/null; then
        echo 'Using the existing BloodHound collector.'
    else
        pipx install --force bloodhound-ce </dev/null
    fi
    if command -v certipy-ad >/dev/null || command -v certipy >/dev/null; then
        echo 'Using the existing Certipy executable.'
    else
        pipx install --force certipy-ad </dev/null
    fi
    if ! $system_install; then
        profile_line='export PATH="$HOME/.local/bin:$PATH"'
        # HARP uses /bin/sh -lc, which reads .profile rather than .zshrc.
        if ! grep -Fqx "$profile_line" "$HOME/.profile" 2>/dev/null; then
            printf '\n# HARP Kali tools\n%s\n' "$profile_line" >> "$HOME/.profile"
        fi
    fi
fi

# Offline synthetic smoke checks. No authorized target or network is contacted.
python3 - <<'PY'
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

commands = ["nmap", "nxc", "timeout", "python3", "curl", "dig", "ip", "nc", "smbclient",
            "ldapsearch", "enum4linux-ng", "evil-winrm", "whatweb", "gobuster", "ssh",
            "impacket-secretsdump", "whippet"]
missing = [name for name in commands if not shutil.which(name)]
groups = {"bloodhound_collector": ["bloodhound-ce-python", "bloodhound-python"],
          "certipy": ["certipy-ad", "certipy"]}
tools = {key: next((name for name in names if shutil.which(name)), None) for key, names in groups.items()}
missing += [" or ".join(groups[key]) for key, name in tools.items() if name is None]
if missing:
    raise SystemExit("Missing tools on PATH: " + ", ".join(missing))

def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise SystemExit("Dependency check failed for " + args[0] + ": " + result.stderr[-2000:])
    return result.stdout

with tempfile.TemporaryDirectory(prefix="harp-deps-") as name:
    fixture = Path(name) / "users.json"
    principal = "HARP-CHECK@EXAMPLE.INVALID"
    sid = "S-1-5-21-1-2-3-1001"
    fixture.write_text(json.dumps({"meta": {"type": "users", "count": 1, "version": 5},
        "data": [{"ObjectIdentifier": sid, "Properties": {"name": principal, "enabled": True}, "Aces": []}]}))
    output = run(["whippet", str(fixture), "--batch", "--batch-ready"],
                 '{"id":"harp-dependency-check","mode":"ping"}\n')
    replies = [json.loads(line) for line in output.splitlines() if line.strip()]
    if (len(replies) != 2 or replies[0].get("event") != "ready"
            or replies[0].get("schema_version") != 1 or replies[0].get("protocol_version") != 1
            or not replies[0].get("session_id")
            or replies[1].get("id") != "harp-dependency-check"
            or replies[1].get("batch", {}).get("session_id") != replies[0]["session_id"]
            or replies[1].get("result", {}).get("status") != "ready"):
        raise SystemExit("Whippet does not satisfy HARP's batch protocol contract")
    ranked = json.loads(run(["whippet", str(fixture), "--from", principal, "--to", principal,
                             "--k-shortest", "1", "--limit", "1"]))
    if ranked.get("result", {}).get("backend") != "NetworkX shortest_simple_paths":
        raise SystemExit("Whippet ranked-path/NetworkX check failed")
    print("Whippet " + replies[0].get("whippet_version", "unknown") + ": batch and NetworkX checks passed")
run([tools["bloodhound_collector"], "--help"])
run([tools["certipy"], "-h"])
print("Detected AD tools: " + ", ".join(tools.values()))
print("HARP Kali dependencies ready. No target was contacted.")
PY
