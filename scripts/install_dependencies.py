"""Provision HARP's Kali tools before a session, using an explicitly chosen runtime."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).with_name("install-dependencies.sh")


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--runtime", choices=("wsl", "docker"), required=True)
    cli.add_argument("--distro", help="Exact WSL distribution configured in HARP")
    cli.add_argument("--user", help="Exact nonroot Kali user configured in HARP")
    cli.add_argument("--image", default="harp-kali:latest", help="Docker tool image tag")
    cli.add_argument("--whippet-ref", default="main", help="Whippet Git branch, tag or commit (default main)")
    cli.add_argument("--check", action="store_true", help="Verify installed tools offline without installing")
    return cli


def plan(args):
    """Return explicit argv/stage pairs; never infer or switch WSL distributions."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", args.whippet_ref):
        raise ValueError("Invalid Whippet Git ref")
    if args.runtime == "wsl":
        for value, label in ((args.distro, "--distro"), (args.user, "--user")):
            if not value or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", value):
                raise ValueError("WSL requires an explicit valid " + label)
        if args.user == "root":
            raise ValueError("--user must name HARP's nonroot Kali session user")

        def wsl(user, options):
            return ["wsl.exe", "--distribution", args.distro, "--user", user, "--exec",
                    "bash", "-s", "--", *options]

        if args.check:
            return [(wsl(args.user, ["--check"]), True)]
        return [(wsl("root", ["--apt-only"]), True),
                (wsl(args.user, ["--python-only", "--whippet-ref", args.whippet_ref]), True)]
    if args.distro or args.user:
        raise ValueError("--distro/--user apply only to WSL")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*", args.image):
        raise ValueError("Invalid Docker image tag")
    if args.check:
        return [(["docker", "run", "--rm", "--network", "none", "--pull=never", args.image, "bash",
                  "/usr/local/share/harp/install-dependencies.sh", "--system", "--check"], False)]
    return [(["docker", "build", "--no-cache", "--build-arg", "WHIPPET_REF=" + args.whippet_ref,
              "-f", str(ROOT / "Dockerfile.kali"), "-t", args.image, str(ROOT)], False),
            (["docker", "run", "--rm", "--network", "none", "--pull=never", args.image, "bash",
              "/usr/local/share/harp/install-dependencies.sh", "--system", "--check"], False)]


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    try:
        commands = plan(args)
    except ValueError as error:
        cli.error(str(error))
    script = SCRIPT.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    print("Checking" if args.check else "Installing", "dependencies for", args.runtime, flush=True)
    for command, stream_script in commands:
        # No target/session commands run here: this is explicit pre-session setup.
        subprocess.run(command, input=script if stream_script else None, cwd=ROOT, check=True,
                       creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    print("Dependency setup complete. Select this same runtime/user in HARP.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("Dependency setup failed. Correct the error above and rerun: " + str(error)) from error
