"""
bruh hub v0.1
Copyright (C) 2026 YourLocalPotato

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
from __future__ import annotations

import argparse
import logging
import struct
from pathlib import Path
from typing import BinaryIO


# --- constants -------------------------------------------------
BRUH_MAGIC = b"BRUH" # 4 bytes
VERSION = b"v0.1" # 4 bytes
_FILENAME_LEN_FMT = ">H"   # unsigned short, big-endian (2 bytes)
_FILESIZE_FMT = ">Q"       # unsigned long long, big-endian (8 bytes)


def setup_logger(level: int = logging.INFO) -> logging.Logger:
    """Create and return a simple logger.

    Use this logger during development. You can change formats/handlers later.
    """
    logger = logging.getLogger("bruh")
    logger.setLevel(level)
    if not logger.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(sh)
    return logger


logger = setup_logger()


def print_startup_banner() -> None:
    print(".bruh hub v0.1")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")


# --- header helpers --------------------------------------------
def write_header(f: BinaryIO, original_name: str, original_size: int) -> None:
    """Write the v0.1 header to file-like `f`.

    Header layout (v0.1): magic(4) | version(4) | name_len(2) | name(bytes) | size(8)
    """
    name_bytes = original_name.encode("utf-8")
    if len(name_bytes) > 0xFFFF:
        raise ValueError("filename too long")
    f.write(BRUH_MAGIC)
    f.write(VERSION)
    f.write(struct.pack(_FILENAME_LEN_FMT, len(name_bytes)))
    f.write(name_bytes)
    f.write(struct.pack(_FILESIZE_FMT, original_size))


def read_header(f: BinaryIO) -> tuple[str, int]:
    """Read header and return (original_name, original_size).

    Raises ValueError on invalid header.
    """
    magic = f.read(len(BRUH_MAGIC))
    if magic != BRUH_MAGIC:
        raise ValueError("Not a .bruh file (bad magic)")
    else:
        version = f.read(len(VERSION))
        if version == VERSION:
            pass
        else:
            raise ValueError(f"Unsupported .bruh version: {version.decode('utf-8')}")
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


# --- turns a normal file into a .bruh file ---------------------------
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
    """
    Gets the original file back from a .bruh file.

    """
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

    

# --- CLI ------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bruh hub v0.1", description="bruh hub v0.1 pack/unpack scaffold")
    sub = p.add_subparsers(dest="cmd", required=True)

    pack = sub.add_parser("pack", help="Pack a single file into a .bruh")
    pack.add_argument("input", type=Path, help="Input file to pack")
    pack.add_argument("output", type=Path, nargs="?", help="Output .bruh path (optional)")

    unpack = sub.add_parser("unpack", help="Unpack a .bruh file")
    unpack.add_argument("bruh", type=Path, help=".bruh file to unpack")
    unpack.add_argument("outdir", type=Path, nargs="?", default=Path.cwd(), help="Directory to restore file into")

    return p


def main(argv: list[str] | None = None) -> int:
    print_startup_banner()
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "pack":
        inp: Path = args.input
        out: Path = args.output if args.output is not None else inp.with_suffix(inp.suffix + ".bruh")
        logger.info("pack: %s -> %s", inp, out)
        try:
            pack_file(inp, out)
        except Exception as e:
            logger.error("pack failed: %s", e)
            return 2
        logger.info("packed successfully")
        return 0

    if args.cmd == "unpack":
        bruh: Path = args.bruh
        outdir: Path = args.outdir
        logger.info("unpack: %s -> %s", bruh, outdir)
        try:
            restored = unpack_file(bruh, outdir)
        except Exception as e:
            logger.error("unpack failed: %s", e)
            return 2
        logger.info("restored: %s", restored)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
