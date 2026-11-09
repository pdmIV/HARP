# Package installation and releases

HARP's distribution and terminal command are named `harp-ai`. Installing it does
not create a `harp` executable. Python 3.10 or newer is required. HARP itself uses
the standard library. Its Kali command-line tools are installed separately in
the selected runtime through the bundled dependency installer.

## Install now from GitHub

On native Kali, install pipx once as your normal user:

```bash
sudo apt update
sudo apt install -y pipx python3-venv git
pipx ensurepath
```

Open a new terminal, then:

```bash
pipx install "git+https://github.com/pdmIV/HARP.git"
sudo -v
harp-ai deps --runtime native
harp-ai
```

On Windows, install Python 3.10+ and Git, then run in PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
```

Open a new terminal:

```powershell
pipx install "git+https://github.com/pdmIV/HARP.git"
harp-ai deps --runtime wsl --distro kali-linux --user kali
harp-ai
```

Prepare Kali WSL first and replace its distribution/user with your actual values.
Choose that same runtime in the dashboard. Dependency setup also remains available
through the dashboard. See [dependency installation](dependencies.md) for the full
tool list, Docker, offline checks, and selecting a reviewed Whippet revision.
For example, `harp-ai deps --runtime native --check` verifies without installing.
Never launch the whole application with sudo.

Installing a wheel is also supported:

```bash
pipx install ./harp_ai-0.5.0-py3-none-any.whl
```

After the project is published to PyPI, the registry install becomes:

```bash
pipx install harp-ai
pipx upgrade harp-ai
```

Until then, upgrade a GitHub-source installation with
`pipx upgrade harp-ai`. Its original Git URL remains the upgrade source.
For repeatable installs, append `@TAG_OR_COMMIT` to the Git URL. A venv with
`python -m pip install .` also works for a local checkout. Avoid installing into
Kali's externally managed system Python with sudo pip or break-system-packages.

## Terminal commands and saved data

| Command | Behavior |
| --- | --- |
| `harp-ai` | Open the local browser command center |
| `harp-ai --version` | Print the shared HARP version |
| `harp-ai --no-browser --port 8765` | Print the private dashboard URL |
| `harp-ai deps --help` | Kali dependency setup options |
| `harp-ai cli --help` | Existing headless session commands |
| `harp-ai mcp` | Stdio MCP adapter for Codex |
| `harp-ai --home /path/to/operator-data` | Use an explicit saved-data directory |

Installed copies save configuration, keys, runs, and control state under
`$XDG_DATA_HOME/harp-ai` (default `~/.local/share/harp-ai`) on Linux or
`%LOCALAPPDATA%\harp-ai` on Windows. Assets stay in the installed package.
`HARP_HOME` overrides the saved-data directory for all entry points. Place
`--home` before a subcommand. Upgrading or uninstalling the package leaves
saved data in place. Existing source checkouts retain their repository-local
data unless `HARP_HOME` is set. Existing data is not copied automatically.
Use settings snapshots/session exports to migrate selectively, or point all
processes at the same existing directory deliberately.

For an installed Codex MCP server, set `command` to the absolute path returned
by `which harp-ai` on Kali or `(Get-Command harp-ai).Source` in PowerShell,
and set `args = ["mcp"]`. It needs no repository working directory. If using a
custom home, set the same `HARP_HOME` for the dashboard and MCP server.
Preserve the existing `terminal_root` approval setting and tool timeout in
[the source configuration](../.codex/config.toml). Do not replace root approvals
with automatic approval.

The wheel contains the web UI, fonts and font license, example configurations,
Docker recipe, dependency installer, and research helper. Explicit build lists
exclude operator configuration, keys, logs, session evidence, and local control
state. Kali/WSL, Docker, VPN access, model runtimes, and API credentials are not
provisioned by pipx. The Docker demo target still requires a source checkout.

## GitHub Actions

`.github/workflows/package.yml` runs for pushes to main, pull requests, and manual
runs. It tests Python 3.10, 3.13, and 3.14 on Linux and Windows, runs the dashboard
JavaScript tests, builds an sdist and a wheel from that sdist, checks metadata
with Twine, and uploads both as `python-distributions` artifacts. Separate clean
venvs install the wheel outside the checkout on Linux/Windows and exercise the
CLI, MCP initialization, HTTP dashboard, static assets, and data isolation.
No model calls, target assessment, or Kali tool installation run in CI.

`.github/workflows/release.yml` runs when a GitHub release is published. It calls
the same validation workflow, requires the tag to match `v` plus
`harp_version.VERSION`, then publishes the tested artifacts to PyPI using OIDC
Trusted Publishing. Only the publish job receives `id-token: write`.

Before the first registry release, configure these once:

1. Create the GitHub environment **pypi** under `pdmIV/HARP` repository settings.
2. On PyPI, add a pending trusted publisher for an available project name
   **harp-ai**, owner **pdmIV**, repository **HARP**, workflow **release.yml**,
   environment **pypi**. For an existing project, add it in that project's
   Publishing settings. The command name is independent of registry-name availability.
3. Set the intended release version in `harp_version.py` and update the changelog.
4. Push the commit and matching `vVERSION` tag, then publish a GitHub release for
   that tag. Pushing a tag alone does not publish with this workflow.

No PyPI API token is required. Publishing a GitHub prerelease also triggers the
workflow; use a corresponding PEP 440 prerelease version such as `0.6.0a1`.
PyPI versions cannot be overwritten, so bump the version for each upload.

For a local package check:

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
python scripts/check_package.py dist
```

Start with an empty `dist` directory for each build. The smoke checker requires
exactly one wheel and one sdist. The build's explicit resource list is in
`setup.py`; update it and the smoke check when adding runtime assets. Version
metadata comes directly from `harp_version.py`.

References: [PyPA packaging and GitHub Actions](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/),
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/).
