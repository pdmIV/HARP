"""Exercise the built package in an isolated venv, outside the source checkout."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import venv
import zipfile


def check_contents(dist):
    wheels = list(dist.glob("*.whl"))
    sources = list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise RuntimeError("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sources[0]) as archive:
        source_names = [name.split("/", 1)[-1] for name in archive.getnames()]
    for names in (wheel_names, source_names):
        for name in names:
            parts = Path(name).parts
            if (any(part in {"runs", ".secrets", ".settings_backups", ".git", ".codex"} for part in parts)
                    or Path(name).name in {"harp.json", ".control_center.json", ".gui_heartbeat"}
                    or name.endswith(".key")):
                raise RuntimeError("Private runtime data included in distribution: " + name)
    required = ["harp.py", "harp_cli.py", "harp_resources.py", "scripts/install_dependencies.py",
                "scripts/install-dependencies.sh", "harp_data/web/index.html",
                "harp_data/web/app.js", "harp_data/web/app.css", "harp_data/web/favicon.svg",
                "harp_data/web/fonts/Chomsky.woff2", "harp_data/web/fonts/LICENSE.txt",
                "harp_data/Dockerfile.kali", "harp_data/harp.htb.example.json",
                "harp_data/scripts/install-dependencies.sh", "harp_data/scripts/research_fetch.py"]
    for name in required:
        if name not in wheel_names:
            raise RuntimeError("Missing packaged resource: " + name)
    return wheels[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path)
    parser.add_argument("--skip-http", action="store_true", help="For restricted local environments; CI always checks HTTP")
    args = parser.parse_args()
    wheel = check_contents(args.dist.resolve())
    with tempfile.TemporaryDirectory(prefix="harp-package-") as temp:
        root = Path(temp)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        binaries = environment / ("Scripts" if os.name == "nt" else "bin")
        python = binaries / ("python.exe" if os.name == "nt" else "python")
        command = binaries / ("harp-ai.exe" if os.name == "nt" else "harp-ai")
        env = dict(os.environ, HARP_HOME=str(root / "operator-data"), PYTHONUNBUFFERED="1")
        env.pop("PYTHONPATH", None)

        def run(args, **kwargs):
            return subprocess.run([str(arg) for arg in args], cwd=root, env=env,
                                  text=True, capture_output=True, check=True, timeout=90, **kwargs)

        run([python, "-m", "pip", "install", "--no-deps", wheel])
        run([python, "-m", "pip", "check"])
        for cli_args in (["--version"], ["--help"], ["deps", "--help"], ["cli", "--help"], ["cli", "report"]):
            run([command, *cli_args])
        # Exercise the packaged installer planning without provisioning the runner.
        run([python, "-c", "from scripts import install_dependencies as i; "
             "assert i.ROOT.joinpath('Dockerfile.kali').is_file(); "
             "assert i.SCRIPT.is_file(); "
             "i.plan(i.parser().parse_args(['--runtime','wsl','--distro','synthetic','--user','labuser','--check']))"])
        reply = run([command, "mcp"], input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                                       "params": {}}) + "\n")
        assert json.loads(reply.stdout)["result"]["serverInfo"]["name"] == "harp"
        # Serve static files through the installed handler, without requiring sockets.
        run([python, "-c", "import io, harp_web; "
             "handler = object.__new__(harp_web.HARPRequestHandler); "
             "handler.path = '/'; handler.wfile = io.BytesIO(); "
             "handler._headers = lambda *args: None; handler.do_GET(); "
             "assert b'<!doctype html>' in handler.wfile.getvalue().lower(); "
             "assert harp_web.draft_config()['target'] == ''"])

        with (root / "dashboard.log").open("w+") as log:
            process = subprocess.Popen([str(command), "--no-browser", "--port", "0"], cwd=root,
                                       env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                control = root / "operator-data" / ".control_center.json"
                deadline = time.monotonic() + 20
                while not control.is_file():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        raise RuntimeError("Installed dashboard failed to start: " + log.read())
                    time.sleep(0.1)
                record = json.loads(control.read_text())
                url = "http://127.0.0.1:" + str(record["port"])
                paths = () if args.skip_http else ("/", "/app.js", "/app.css", "/favicon.svg", "/fonts/Chomsky.woff2", "/api/state")
                for path in paths:
                    request = urllib.request.Request(url + path, headers={"X-HARP-Token": record["token"]})
                    with urllib.request.urlopen(request, timeout=10) as response:
                        assert response.status == 200 and response.read(), path
                # No configuration or sessions should appear in site-packages.
                run([python, "-c", "import harp_paths; "
                     "assert harp_paths.data_dir() != harp_paths.assets_dir(); "
                     "assert not harp_paths.assets_dir().joinpath('harp.json').exists()"])
            finally:
                process.terminate()
                process.wait(timeout=10)
    print("Installed wheel: CLI, MCP, dashboard assets and data isolation passed.")
    if args.skip_http:
        print("HTTP requests explicitly skipped; dashboard startup and direct static serving checked.")


if __name__ == "__main__":
    main()
