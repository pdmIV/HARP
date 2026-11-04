"""Prompt for and encrypt an Unsloth API key for HARP without shell history."""

from pathlib import Path
from getpass import getpass

from harp_secret import save_key


if __name__ == "__main__":
    destination = Path(__file__).resolve().parent / ".secrets" / "unsloth.key"
    save_key(destination, getpass("Paste your Unsloth API key (input hidden): "))
    print("Key saved encrypted for your Windows account. Codex does not need a restart.")
