"""Discover optional local Kali resources without contacting a target."""

import json
import shlex


SECLISTS_PROBE = """
import json
from pathlib import Path
home = Path.home()
candidates = [Path('/usr/share/seclists'), Path('/usr/share/SecLists'),
              Path('/usr/share/wordlists/seclists'), Path('/opt/SecLists'),
              home / 'SecLists', home / 'seclists', home / 'tools' / 'SecLists']
roots = []
for candidate in candidates:
    if candidate.is_dir():
        root = candidate.resolve()
        if str(root) not in roots:
            roots.append(str(root))
categories = [name for name in ('Discovery', 'Passwords', 'Usernames', 'Fuzzing')
              if roots and (Path(roots[0]) / name).is_dir()]
print(json.dumps({'available': bool(roots), 'roots': roots,
                  'categories': categories}, separators=(',', ':')))
"""
CHECK_COMMAND = "python3 -c " + shlex.quote(SECLISTS_PROBE)


def check(terminal):
    result = terminal.run(CHECK_COMMAND, 10, live=False)
    if result.get("exit_code") != 0 or result.get("truncated"):
        raise RuntimeError("SecLists discovery did not complete")
    data = json.loads(str(result.get("output", "")).strip())
    if (not isinstance(data, dict) or type(data.get("available")) is not bool
            or not isinstance(data.get("roots"), list)
            or not isinstance(data.get("categories"), list)
            or any(not isinstance(path, str) or not path.startswith("/") for path in data["roots"])):
        raise ValueError("Invalid SecLists discovery response")
    return data, result
