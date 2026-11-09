"""HARP-owned Whippet NDJSON transport; no imports from Whippet's pipx environment."""

import atexit
import collections
import copy
import json
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid


# These scripts execute only through the session's runtime adapter. A process
# identity includes Linux start time, so cleanup never signals a reused PID.
SNAPSHOT = r'''
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve(strict=True)
files=[]
for name in json.loads(sys.argv[2]):
 p=(root/name).resolve(strict=True)
 if not p.is_relative_to(root) or not p.is_file():
  raise ValueError("Capture must be a regular file under the session workspace")
 h=hashlib.sha256()
 with p.open("rb") as f:
  for chunk in iter(lambda:f.read(1048576),b""): h.update(chunk)
 files.append({"path":str(p),"sha256":h.hexdigest()})
print(json.dumps(files,separators=(",",":")))
'''

LAUNCH = r'''
import json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve(strict=True)
token=sys.argv[2]
exe=sys.argv[3]
files=json.loads(sys.argv[4])
os.chdir(root)
if os.getpgrp()!=os.getpid(): os.setsid()
pid=os.getpid()
start=pathlib.Path("/proc/%s/stat"%pid).read_text().rsplit(")",1)[1].split()[19]
marker=root/(".harp-whippet-"+token+".json")
cancel=root/(".harp-whippet-"+token+".cancel")
if cancel.exists():sys.exit(0)
temporary=marker.with_suffix(".tmp")
with temporary.open("x") as f: json.dump({"pid":pid,"start":start},f)
temporary.replace(marker)
if cancel.exists():
 marker.unlink(missing_ok=True);sys.exit(0)
os.execv(exe,[exe]+[x["path"] for x in files]+["--batch","--batch-ready"])
'''

CLEANUP = r'''
import json,os,pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1]).resolve(strict=True)
marker=root/(".harp-whippet-"+sys.argv[2]+".json")
cancel=root/(".harp-whippet-"+sys.argv[2]+".cancel")
cancel.touch()
if not marker.exists():
 print("absent");sys.exit(0)
data=json.loads(marker.read_text());pid=data["pid"]
def alive():
 try:
  stat=pathlib.Path("/proc/%s/stat"%pid).read_text().rsplit(")",1)[1].split()
  return stat[19]==data["start"] and stat[0]!="Z"
 except FileNotFoundError:return False
if alive():
 if os.getpgid(pid)!=pid:raise RuntimeError("Whippet process group identity changed")
 os.killpg(pid,signal.SIGKILL)
 for _ in range(40):
  if not alive():break
  time.sleep(.05)
 if alive():raise RuntimeError("Runtime Whippet process did not exit")
marker.unlink(missing_ok=True)
cancel.unlink(missing_ok=True)
print("verified-exited")
'''

MODES = {"handoff", "summary", "triage", "objects", "findings", "node", "search", "memberships",
         "members", "users", "reachable", "path", "routes", "ranked-paths", "explain",
         "gpo-scope", "trust-path", "catalog", "ping"}
_clients = {}
_lock = threading.RLock()


def validate(inputs, request):
    if (not isinstance(inputs, list) or not 1 <= len(inputs) <= 32
            or any(not isinstance(x, str) or not x or len(x) > 4096 or "\x00" in x for x in inputs)):
        raise ValueError("Supply 1 through 32 capture file paths in the Kali workspace")
    if not isinstance(request, dict) or request.get("mode") not in MODES or "id" in request:
        raise ValueError("Supply one supported query object without id; HARP owns correlation IDs")
    if set(request) & {"verified_access", "overlay", "overlay-update", "auth_context", "live_access"}:
        raise ValueError("Model requests cannot supply live-access verification or overlay updates")
    if request.get("mode") == "handoff":
        if (not isinstance(request.get("node"), str) or not request["node"]
                or ("query" in request and not isinstance(request["query"], str))
                or ("lead_index" in request and (type(request["lead_index"]) is not int
                                               or request["lead_index"] < 0))):
            raise ValueError("Handoff requires a principal node, optional query and nonnegative lead_index")
    if len(json.dumps(request, ensure_ascii=True)) > 64000:
        raise ValueError("Whippet query is too large")


class Batch:
    def __init__(self, run_dir, terminal, files, executable, event_sink,
                 *, startup_timeout=60, request_timeout=30, response_cap=8 * 1024 * 1024):
        self.run_dir, self.terminal, self.files = Path(run_dir), terminal, files
        self.workspace = getattr(terminal, "workspace", "/workspace")
        self.event_sink = event_sink
        self.startup_timeout, self.request_timeout, self.response_cap = startup_timeout, request_timeout, response_cap
        self.token, self.process, self.ready = uuid.uuid4().hex, None, None
        self.queue = queue.Queue(maxsize=2)
        self.stderr = collections.deque(maxlen=100)
        self.closed = threading.Event()
        self.request_lock = threading.Lock()
        self.index = 0
        self.cache = {}
        self.executable = executable

    def event(self, kind, **fields):
        self.event_sink({"type": "whippet_batch_" + kind, "runtime": self.terminal.cfg.get("runtime", "docker"),
                         "container": self.terminal.name, "process_token": self.token, **fields})

    def cancelled(self):
        return any((self.run_dir / x).exists() for x in (".stop_session", ".stop_local"))

    def _put(self, value):
        while not self.closed.is_set():
            try:
                self.queue.put(value, timeout=.2)
                return
            except queue.Full:
                pass

    def _read(self):
        try:
            while not self.closed.is_set():
                line = self.process.stdout.readline(self.response_cap + 1)
                if not line:
                    raise EOFError("Whippet closed stdout")
                if len(line) > self.response_cap:
                    raise ValueError("Whippet response exceeds HARP's capture limit")
                self._put((json.loads(line), len(line.encode("utf-8"))))
        except Exception as error:
            self._put(error)

    def _diagnostics(self):
        try:
            while not self.closed.is_set():
                line = self.process.stderr.readline(4096)
                if not line:
                    return
                self.stderr.append(line.rstrip())
        except (OSError, ValueError):
            pass

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.cancelled():
                raise RuntimeError("Whippet cancelled by operator")
            try:
                item = self.queue.get(timeout=min(.2, max(.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if isinstance(item, Exception):
                raise item
            value, size = item
            if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
                raise ValueError("Incompatible Whippet response schema")
            return value, size
        raise TimeoutError("Whippet response timed out")

    def start(self):
        manifest = self.run_dir / "whippet_batch.json"
        # Exclusive ownership across HARP processes sharing a session directory.
        with manifest.open("x", encoding="utf-8") as out:
            json.dump({"token": self.token, "workspace": self.workspace}, out)
        try:
            argv = self.terminal.batch_argv(LAUNCH, [self.workspace, self.token, self.executable,
                                                    json.dumps(self.files)])
            self.event("start", inputs=self.files)
            started = time.monotonic()
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
            self.threads = [threading.Thread(target=self._read, daemon=True),
                            threading.Thread(target=self._diagnostics, daemon=True)]
            for thread in self.threads:
                thread.start()
            ready, size = self.receive(self.startup_timeout)
            if (ready.get("event") != "ready" or type(ready.get("protocol_version")) is not int
                    or ready["protocol_version"] != 1 or not isinstance(ready.get("session_id"), str)
                    or not ready["session_id"] or not isinstance(ready.get("modes"), list)
                    or not {"triage", "ping", "shutdown"}.issubset(ready["modes"])):
                raise ValueError("Incompatible Whippet readiness handshake")
            if (type(ready.get("max_request_characters", 65536)) is not int
                    or not 1 <= ready.get("max_request_characters", 65536) <= 65536):
                raise ValueError("Invalid Whippet request size contract")
            self.ready = ready
            self.event("ready", response=ready, wall_seconds=round(time.monotonic() - started, 4), bytes=size)
            return self
        except Exception:
            self.close()
            raise

    def request(self, request):
        if not self.request_lock.acquire(blocking=False):
            raise RuntimeError("A Whippet query is already in flight")
        try:
            if self.closed.is_set() or self.ready is None:
                raise RuntimeError("Whippet process is not ready")
            if self.cancelled():
                self.close()
                raise RuntimeError("Whippet cancelled by operator")
            if request["mode"] not in self.ready["modes"]:
                raise ValueError("Query mode not advertised by Whippet")
            cache_key = json.dumps(request, sort_keys=True, separators=(",", ":"))
            if cache_key in self.cache and self.process.poll() is None:
                response = copy.deepcopy(self.cache[cache_key])
                self.event("cache_hit", request=request, response_id=response["id"],
                           session_id=self.ready["session_id"])
                response["harp_cache"] = {"reused": True, "response_id": response["id"]}
                return response
            request = {**request, "id": uuid.uuid4().hex}
            line = json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n"
            if len(line) > min(65536, self.ready.get("max_request_characters", 65536)):
                raise ValueError("Whippet request exceeds protocol limit")
            try:
                self.event("request", request=request, session_id=self.ready["session_id"])
            except Exception:
                self.close()
                raise
            started = time.monotonic()
            # A writer thread makes pipe backpressure subject to the same deadline.
            def write():
                try:
                    self.process.stdin.write(line)
                    self.process.stdin.flush()
                except (OSError, ValueError) as error:
                    self._put(error)
            writer = threading.Thread(target=write, daemon=True)
            writer.start()
            try:
                response, size = self.receive(self.request_timeout)
                batch = response.get("batch")
                if (response.get("id") != request["id"] or not isinstance(batch, dict)
                        or batch.get("session_id") != self.ready["session_id"]
                        or type(batch.get("request_index")) is not int or batch["request_index"] != self.index + 1
                        or ("error" not in response and response.get("mode") not in (request["mode"], "reach"))):
                    raise ValueError("Whippet response correlation mismatch")
                self.index += 1
                self.event("response", response=response, bytes=size,
                           wall_seconds=round(time.monotonic() - started, 4), stderr=list(self.stderr))
                if "error" not in response and request["mode"] != "ping":
                    if len(self.cache) >= 32:
                        self.cache.pop(next(iter(self.cache)))
                    self.cache[cache_key] = copy.deepcopy(response)
                return response
            except Exception as error:
                try:
                    self.event("error", error=str(error), request_id=request["id"], stderr=list(self.stderr))
                finally:
                    self.close()
                raise
            finally:
                writer.join(timeout=1)
        finally:
            self.request_lock.release()

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        # Graceful EOF first. Never block closing stdin behind a stuck writer.
        process = self.process
        if process is not None and process.poll() is None:
            closer = threading.Thread(target=lambda: _close_pipe(process.stdin), daemon=True)
            closer.start()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        try:
            cleanup(self.run_dir, self.terminal, self.event_sink, expected_token=self.token)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
                for thread in getattr(self, "threads", []):
                    thread.join(timeout=1)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    _close_pipe(pipe)
                self.event("exit", launcher_exit_code=process.poll(), stderr=list(self.stderr))


def _close_pipe(pipe):
    try:
        pipe.close()
    except (OSError, ValueError):
        pass


def cleanup(run_dir, terminal, event_sink, *, expected_token=None):
    manifest = Path(run_dir) / "whippet_batch.json"
    if not manifest.exists():
        return
    record = json.loads(manifest.read_text(encoding="utf-8"))
    if expected_token is not None and record["token"] != expected_token:
        event_sink({"type": "whippet_batch_cleanup", "process_token": expected_token,
                    "status": "ownership_changed; current connection preserved"})
        return
    try:
        result = subprocess.run(terminal.batch_argv(CLEANUP, [record["workspace"], record["token"]]),
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        event_sink({"type": "whippet_batch_cleanup", "process_token": record["token"], "error": str(error)})
        raise RuntimeError("Whippet runtime cleanup could not be verified") from error
    event_sink({"type": "whippet_batch_cleanup", "process_token": record["token"],
                "exit_code": result.returncode, "output": result.stdout, "stderr": result.stderr})
    if result.returncode != 0:
        raise RuntimeError("Whippet runtime cleanup could not be verified; inspect cleanup event")
    manifest.unlink(missing_ok=True)


def query(run_dir, terminal, inputs, request, executable, event_sink, *, refresh=False, timeout=30):
    validate(inputs, request)
    key = str(Path(run_dir).resolve())
    with _lock:
        failed = Path(run_dir) / "whippet_batch_failed.json"
        if failed.exists() and not refresh:
            raise RuntimeError("Whippet batch failed earlier; explicitly refresh to start a new process")
        # A local snapshot check also verifies symlink-resolved workspace boundaries.
        started = time.monotonic()
        result = subprocess.run(terminal.batch_argv(SNAPSHOT, [getattr(terminal, "workspace", "/workspace"), json.dumps(inputs)]),
                                capture_output=True, text=True, timeout=30)
        event_sink({"type": "whippet_batch_snapshot", "inputs": inputs, "exit_code": result.returncode,
                    "wall_seconds": round(time.monotonic() - started, 4), "stderr": result.stderr[-4000:]})
        if result.returncode:
            raise ValueError("Capture validation failed inside the selected runtime: " + result.stderr[-1000:])
        files = json.loads(result.stdout)
        client = _clients.get(key)
        if client and client.request_lock.locked():
            raise RuntimeError("A Whippet query is already in flight")
        if client and (refresh or client.files != files or client.closed.is_set()):
            client.close()
            _clients.pop(key, None)
            client = None
        if refresh:
            # Can clean a process owned by another HARP launcher using recorded identity.
            cleanup(run_dir, terminal, event_sink)
            failed.unlink(missing_ok=True)
        if client is None:
            client = Batch(run_dir, terminal, files, executable, event_sink, request_timeout=timeout)
            try:
                client.start()
            except Exception as error:
                failed.write_text(json.dumps({"error": str(error)}), encoding="utf-8")
                event_sink({"type": "whippet_batch_error", "error": str(error), "phase": "startup"})
                raise RuntimeError("Whippet startup failed; review error before explicit refresh: " + str(error)) from error
            _clients[key] = client
    try:
        return client.request(request)
    except Exception as error:
        if client.closed.is_set():
            failed.write_text(json.dumps({"error": str(error)}), encoding="utf-8")
            raise RuntimeError("Whippet transport failed; review error before explicit refresh: " + str(error)) from error
        raise


def close_session(run_dir, terminal, event_sink):
    with _lock:
        client = _clients.pop(str(Path(run_dir).resolve()), None)
        if client:
            client.close()
        cleanup(run_dir, terminal, event_sink)


def close_all():
    for client in list(_clients.values()):
        try:
            client.close()
        except Exception:
            pass  # Manifest remains for explicit runtime cleanup on next session access.
    _clients.clear()


atexit.register(close_all)
