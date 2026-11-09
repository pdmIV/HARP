"""Cached offline runtime checks and explicitly requested dependency installation."""
import collections
import copy
import json
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import harp_paths

from scripts import install_dependencies as installer


PROBE = r'''
import json,shutil,subprocess,tempfile
from pathlib import Path
commands="nmap nxc timeout python3 curl dig ip nc smbclient ldapsearch enum4linux-ng evil-winrm whatweb gobuster ssh impacket-secretsdump whippet".split()
missing=[x for x in commands if not shutil.which(x)]
groups={"bloodhound_collector":["bloodhound-ce-python","bloodhound-python"],"certipy":["certipy-ad","certipy"]}
tools={key:next((name for name in names if shutil.which(name)),None) for key,names in groups.items()}
for key,names in groups.items():
 if not tools[key]:missing.append(" or ".join(names))
tools["smb_enumerator"]=next((x for x in ["enum4linux-ng","enum4linux"] if shutil.which(x)),None)
issues=["Missing tools: "+", ".join(missing)] if missing else []
if "whippet" not in missing:
 try:
  with tempfile.TemporaryDirectory(prefix="harp-check-") as name:
   fixture=Path(name)/"users.json"
   principal="HARP-CHECK@EXAMPLE.INVALID"
   fixture.write_text(json.dumps({"meta":{"type":"users","version":5,"count":1},"data":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1001","Properties":{"name":principal,"enabled":True},"Aces":[]}]}))
   r=subprocess.run(["whippet",str(fixture),"--batch","--batch-ready"],input='{"id":"check","mode":"ping"}\n',capture_output=True,text=True,timeout=6)
   rows=[json.loads(x) for x in r.stdout.splitlines() if x.strip()]
   if r.returncode or len(rows)!=2 or rows[0].get("event")!="ready" or rows[0].get("protocol_version")!=1 or rows[0].get("schema_version")!=1 or rows[1].get("id")!="check" or not rows[0].get("session_id") or rows[1].get("batch",{}).get("session_id")!=rows[0]["session_id"] or rows[1].get("result",{}).get("status")!="ready":
    issues.append("Whippet needs compatible batch support; run the dependency installer.")
   r=subprocess.run(["whippet",str(fixture),"--from",principal,"--to",principal,"--k-shortest","1"],capture_output=True,text=True,timeout=6)
   if r.returncode or json.loads(r.stdout).get("result",{}).get("backend")!="NetworkX shortest_simple_paths":
    issues.append("Whippet ranked-path support is missing or incompatible (NetworkX).")
 except Exception as error:
  issues.append("Whippet verification failed: "+str(error)[:300])
print(json.dumps({"issues":issues,"missing":missing,"tools":tools}))
'''


def options(cfg, check=False):
    runtime = cfg.get("runtime", "docker")
    if runtime not in ("wsl", "native", "docker"):
        raise ValueError("Choose WSL, native Kali, or Docker in Configuration")
    args = ["--runtime", runtime]
    if runtime == "wsl":
        args += ["--distro", cfg.get("wsl_distro", "kali-linux"), "--user", cfg.get("wsl_user", "kali")]
    if check:
        args += ["--check"]
    parsed = installer.parser().parse_args(args)
    installer.plan(parsed)  # Same runtime/name validation as the standalone installer.
    return args


def identity(cfg):
    args = options(cfg)
    return json.dumps(args, separators=(",", ":"))


class DependencyManager:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.cache = {}
        self.checking = set()
        self.installation = None

    @property
    def installing(self):
        with self.lock:
            return bool(self.installation and self.installation["status"] == "installing")

    def base(self, cfg):
        args = options(cfg)
        native = cfg.get("runtime") == "native"
        launcher = (("python3" if native else "python") + " scripts/install_dependencies.py"
                    if harp_paths.source_checkout() else "harp-ai deps")
        return {"key": identity(cfg), "runtime": cfg.get("runtime", "docker"),
                "target": (f"WSL {cfg.get('wsl_distro', 'kali-linux')} / {cfg.get('wsl_user', 'kali')}"
                           if cfg.get("runtime") == "wsl" else "Native Kali / current user" if cfg.get("runtime") == "native" else "Docker harp-kali:latest"),
                "command": ("sudo -v && " if native else "") + launcher + " " + " ".join(args)}

    def status(self, cfg, force=False):
        try:
            base = self.base(cfg)
        except ValueError as error:
            return {"status": "warning", "issues": [str(error)], "target": "Runtime not configured", "key": "", "command": ""}
        key = base["key"]
        with self.lock:
            if self.installation and self.installation["key"] == key and self.installation["status"] == "installing":
                return {**base, "status": "installing", "issues": [], "installation": copy.deepcopy(self.installation)}
            cached = self.cache.get(key)
            if (force or cached is None or time.monotonic() - cached[0] > 300) and key not in self.checking:
                self.checking.add(key)
                threading.Thread(target=self._check, args=(copy.deepcopy(cfg), base), daemon=True).start()
            result = {**base, **(cached[1] if cached else {"status": "checking", "issues": []}),
                      "checking": key in self.checking}
            if self.installation and self.installation["key"] == key:
                result["installation"] = copy.deepcopy(self.installation)
            return result

    def _check(self, cfg, base):
        try:
            if cfg.get("runtime") == "wsl":
                argv = ["wsl.exe", "--distribution", cfg.get("wsl_distro", "kali-linux"), "--user", cfg.get("wsl_user", "kali"),
                        "--exec", "/bin/sh", "-lc", "exec timeout 20s python3 -c " + shlex.quote(PROBE)]
            elif cfg.get("runtime") == "native":
                argv = ["timeout", "20s", "python3", "-c", PROBE]
            else:
                argv = ["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                        "harp-kali:latest", "timeout", "20s", "python3", "-c", PROBE]
            result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=25,
                                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout)[-1500:] or "Runtime could not run the check")
            report = json.loads(result.stdout)
            issues = report["issues"]
            status = {"status": "warning" if issues else "ready", "issues": issues, "tools": report.get("tools", {})}
        except Exception as error:
            status = {"status": "warning", "issues": ["Unable to verify this runtime: " + str(error)[:1500]]}
        with self.lock:
            self.cache[base["key"]] = (time.monotonic(), status)
            self.checking.discard(base["key"])

    def install(self, cfg, expected_key):
        base = self.base(cfg)
        if expected_key != base["key"]:
            raise ValueError("Runtime selection changed. Reopen dependency setup before installing.")
        with self.lock:
            if self.installing or self.checking:
                raise ValueError("Wait for the current dependency operation to finish")
            self.installation = {"key": base["key"], "target": base["target"], "status": "installing",
                                 "started": time.monotonic(), "logs": [], "message": "Installing tools and running offline checks."}
        threading.Thread(target=self._install, args=(copy.deepcopy(cfg), base), daemon=True).start()

    def _install(self, cfg, base):
        logs = collections.deque(maxlen=150)
        try:
            argv = [sys.executable, str(Path(installer.__file__).resolve()), *options(cfg)]
            if cfg.get("runtime") == "native":
                argv += ["--native-auth", "polkit"]
            process = subprocess.Popen(argv, cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace", bufsize=1,
                                       creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            try:
                for line in process.stdout:
                    logs.append(line.rstrip()[:2000])
                    with self.lock:
                        self.installation["logs"] = list(logs)
                code = process.wait()
            finally:
                process.stdout.close()
            if code:
                raise RuntimeError("Installation failed. Review the output and retry after resolving the error.")
            state, message = "ready", "Dependencies installed and verified. You're ready to start a session."
        except Exception as error:
            state, message = "warning", str(error)
            logs.append(message)
        with self.lock:
            self.installation.update(status=state, message=message, logs=list(logs))
            self.cache[base["key"]] = (time.monotonic(), {"status": state, "issues": [] if state == "ready" else [message]})
