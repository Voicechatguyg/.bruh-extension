"""Simple interactive launcher for .bruh pack/unpack (beginner-friendly).

This script asks the user whether to pack or unpack, prompts for paths,
and invokes the existing `bruh_creator.py` CLI to perform the action.

Usage: run `python bruh_cli.py` and follow prompts.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).parent
BRUH_CREATOR = ROOT / "bruh_creator.py"


def print_startup_banner() -> None:
    print(".bruh hub v0.2")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")


def run_command(args: list[str]) -> int:
    proc = subprocess.run(args, text=True)
    return proc.returncode


def prompt_path(prompt: str) -> Path:
    while True:
        p = input(prompt).strip()
        if not p:
            print("Please enter a path.")
            continue
        return Path(p)


def main() -> None:
    print_startup_banner()
    while True:
        choice = input("Pack or unpack? (p/u) or q to quit: ").strip().lower()
        if choice in ("q", "quit"):
            print("Bye")
            return
        if choice == "p":
            inp = prompt_path("Path of file to pack: ")
            default_out = inp.with_suffix(inp.suffix + ".bruh")
            out = input(f"Output path (ENTER for {default_out}): ").strip()
            out_path = Path(out) if out else default_out
            # If user provided an existing directory, place the .bruh inside it
            if out_path.exists() and out_path.is_dir():
                out_path = out_path / (inp.name + ".bruh")
                print(f"Output is a directory — using {out_path}")
            args = ["python", str(BRUH_CREATOR), "pack", str(inp), str(out_path)]
            print("Running:", " ".join(args))
            run_command(args)
        elif choice == "u":
            bruh = prompt_path("Path of .bruh file to unpack: ")
            outdir = input("Output directory (ENTER for current folder): ").strip()
            outdir_path = Path(outdir) if outdir else Path.cwd()
            # If user accidentally passed a file path, use its parent as the directory
            if outdir_path.exists() and outdir_path.is_file():
                print(f"Provided output is a file — using its parent directory {outdir_path.parent}")
                outdir_path = outdir_path.parent
            args = ["python", str(BRUH_CREATOR), "unpack", str(bruh), str(outdir_path)]
            print("Running:", " ".join(args))
            run_command(args)
        else:
            print("Invalid option — enter 'p' to pack, 'u' to unpack, or 'q' to quit.")


if __name__ == "__main__":
    main()
