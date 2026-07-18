"""
bruh hub v0.2
Copyright (C) 2026 YourLocalPotato

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
#--- imports ---------------------------------------------------------------
from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import BinaryIO

#--- version ---------------------------------------------------------
# v0.2:
# - basic .bruh file packing/unpacking
# - added interactive CLI for packing/unpacking files instead of terminal arguments
# --- constants -------------------------------------------------

BRUH_MAGIC = b"BRUH"  # 4 bytes
VERSION = b"v0.2"  # 4 bytes

SUPPORTED_VERSIONS = (
    b"v0.1",
    b"v0.2"
)

_FILENAME_LEN_FMT = ">H"
_FILESIZE_FMT = ">Q"


# --- logging ---------------------------------------------------

def setup_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("bruh")
    logger.setLevel(level)

    if not logger.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(sh)

    return logger


logger = setup_logger()


# --- startup ---------------------------------------------------

def print_startup_banner() -> None:
    print(".bruh hub v0.2")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")
    print()


# --- header helpers --------------------------------------------

def write_header(f: BinaryIO, original_name: str, original_size: int) -> None:
    name_bytes = original_name.encode("utf-8")

    if len(name_bytes) > 0xFFFF:
        raise ValueError("filename too long")

    f.write(BRUH_MAGIC)
    f.write(VERSION)
    f.write(struct.pack(_FILENAME_LEN_FMT, len(name_bytes)))
    f.write(name_bytes)
    f.write(struct.pack(_FILESIZE_FMT, original_size))


def read_header(f: BinaryIO) -> tuple[str, int]:
    magic = f.read(len(BRUH_MAGIC))

    if magic != BRUH_MAGIC:
        raise ValueError("Not a .bruh file (bad magic)")

    version = f.read(len(VERSION))

    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported .bruh version: {version.decode('utf-8')}")
    else:
        pass # Version is supported; proceed with reading the header    
    raw = f.read(struct.calcsize(_FILENAME_LEN_FMT))

    if len(raw) != struct.calcsize(_FILENAME_LEN_FMT):
        raise ValueError("Unexpected EOF while reading filename length")

    (name_len,) = struct.unpack(_FILENAME_LEN_FMT, raw)

    name_bytes = f.read(name_len)

    if len(name_bytes) != name_len:
        raise ValueError("Unexpected EOF while reading filename")

    raw = f.read(struct.calcsize(_FILESIZE_FMT))

    if len(raw) != struct.calcsize(_FILESIZE_FMT):
        raise ValueError("Unexpected EOF while reading file size")

    (original_size,) = struct.unpack(_FILESIZE_FMT, raw)

    name = name_bytes.decode("utf-8")

    return name, original_size


# --- bruh functions --------------------------------------------

def pack_file(input_path: Path, output_path: Path) -> None:
    logger.info("reading file data from %s", input_path)

    data = input_path.read_bytes()

    logger.info("File data read successfully.")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("creating bruh file at %s", output_path)

    with output_path.open("wb") as f:
        write_header(
            f,
            input_path.name,
            len(data)
        )

        f.write(data)


def unpack_file(bruh_path: Path, output_dir: Path) -> Path:
    logger.info("reading bruh file from %s", bruh_path)

    if not bruh_path.is_file():
        raise FileNotFoundError(f".bruh not found: {bruh_path}")

    with bruh_path.open("rb") as f:
        filename, filesize = read_header(f)

        logger.info("found file %s (%s bytes)", filename, filesize)

        data = f.read(filesize)

    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / filename

    output_path.write_bytes(data)

    return output_path


# --- UI helpers ------------------------------------------------

def prompt_path(prompt: str) -> Path:
    while True:
        p = input(prompt).strip()

        if not p:
            print("Please enter a path.")
            continue

        return Path(p)


# --- main program ----------------------------------------------

def main() -> None:
    print_startup_banner()

    while True:
        choice = input(
            "Pack or unpack? (p/u) or q to quit: "
        ).strip().lower()

        if choice in ("q", "quit"):
            print("Bye")
            return


        if choice == "p":
            inp = prompt_path(
                "Path of file to pack: "
            )

            default_out = inp.with_suffix(
                inp.suffix + ".bruh"
            )

            out = input(
                f"Output path (ENTER for {default_out}): "
            ).strip()

            out_path = Path(out) if out else default_out


            if out_path.exists() and out_path.is_dir():
                out_path = out_path / (inp.name + ".bruh")
                print(
                    f"Output is a directory — using {out_path}"
                )


            try:
                print("Packing...")
                pack_file(inp, out_path)
                logger.info("packed successfully")

            except Exception as e:
                logger.error("pack failed: %s", e)



        elif choice == "u":
            bruh = prompt_path(
                "Path of .bruh file to unpack: "
            )

            outdir = input(
                "Output directory (ENTER for current folder): "
            ).strip()

            outdir_path = (
                Path(outdir)
                if outdir
                else Path.cwd()
            )


            if outdir_path.exists() and outdir_path.is_file():
                print(
                    f"Provided output is a file — using its parent directory {outdir_path.parent}"
                )
                outdir_path = outdir_path.parent


            try:
                print("Unpacking...")

                restored = unpack_file(
                    bruh,
                    outdir_path
                )

                logger.info(
                    "restored: %s",
                    restored
                )

            except Exception as e:
                logger.error(
                    "unpack failed: %s",
                    e
                )


        else:
            print(
                "Invalid option — enter 'p', 'u', or 'q'."
            )


if __name__ == "__main__":
    main()