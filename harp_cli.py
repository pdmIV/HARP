"""Installed terminal entry point. Bare harp-ai opens the command center."""
import argparse
import os
import subprocess
import sys

import harp_version


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="HARP " + harp_version.VERSION)
    parser.add_argument("--home", help="Operator data directory (also HARP_HOME); place before the subcommand")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard loopback port")
    parser.add_argument("--no-browser", action="store_true", help="Print the private dashboard URL")
    commands = parser.add_subparsers(dest="command")
    # Let each existing command own its argument validation and help.
    for name, help_text in (("deps", "Install/check tools in an explicit Kali runtime"),
                            ("cli", "Headless session commands; use cli --help"),
                            ("mcp", "Run the stdio MCP server")):
        command = commands.add_parser(name, help=help_text, add_help=False)
        command.add_argument("arguments", nargs=argparse.REMAINDER)
    # parse_known_args allows a subcommand's flags, including its --help.
    args, remaining = parser.parse_known_args(argv)
    forwarded = remaining + getattr(args, "arguments", [])
    if args.home:
        from pathlib import Path
        os.environ["HARP_HOME"] = str(Path(args.home).expanduser().resolve())
    try:
        if args.command == "deps":
            from scripts.install_dependencies import main as install
            install(forwarded)
        elif args.command == "cli":
            import harp
            harp.main(forwarded)
        elif args.command == "mcp":
            if forwarded:
                parser.error("mcp does not accept arguments")
            import harp_paths
            harp_paths.ensure_data_dir()
            import harp_mcp
            harp_mcp.main()
        else:
            if forwarded:
                parser.error("unrecognized arguments: " + " ".join(forwarded))
            import harp_web
            options = ["--port", str(args.port)]
            if args.no_browser:
                options.append("--no-browser")
            harp_web.main(options)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print("HARP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
