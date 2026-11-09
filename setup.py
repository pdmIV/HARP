"""Bundle an explicit resource list without moving the source-checkout interface."""
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        super().run()
        source = Path(__file__).parent
        destination = Path(self.build_lib) / "harp_data"
        # Never recursively copy the checkout: it may contain keys and session evidence.
        resources = [
            "Dockerfile.kali", "harp.example.json", "harp.htb.example.json",
            "harp.native.example.json", "scripts/install-dependencies.sh",
            "scripts/research_fetch.py", "web/index.html", "web/app.js",
            "web/app.css", "web/favicon.svg", "web/fonts/Chomsky.woff2",
            "web/fonts/LICENSE.txt",
        ]
        for name in resources:
            output = destination / name
            output.parent.mkdir(parents=True, exist_ok=True)
            self.copy_file(str(source / name), str(output))


setup(cmdclass={"build_py": BuildPy})
