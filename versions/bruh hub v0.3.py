from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import BinaryIO
import getpass

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - helpful fallback message when dependency missing
    AESGCM = None


# --- constants -------------------------------------------------

# magic string for v0.3
BRUH_MAGIC = b"BRUHv0.3\x00"
_FILENAME_LEN_FMT = ">H"
_FILESIZE_FMT = ">Q"

# encryption mode bytes
ENC_NONE = b"N"  # no encryption
ENC_PU = b"P"    # public / built-in key
ENC_PR = b"R"    # private / user-supplied key

# built-in key (32 bytes) for PU mode — change for your deployment
_BUILTIN_KEY = b"bruh-built-in-key-must-be-32-bytes!!"[:32]


def setup_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("bruh")
    logger.setLevel(level)
    if not logger.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(sh)
    return logger


logger = setup_logger()


def print_startup_banner() -> None:
    print(".bruh hub v0.3")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")
    print()


# --- header helpers --------------------------------------------
def _pack_u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _unpack_u32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def write_header_plain(f: BinaryIO, original_name: str, original_size: int) -> None:
    name_bytes = original_name.encode("utf-8")
    if len(name_bytes) > 0xFFFF:
        raise ValueError("filename too long")
    f.write(BRUH_MAGIC)
    f.write(ENC_NONE)
    f.write(struct.pack(_FILENAME_LEN_FMT, len(name_bytes)))
    f.write(name_bytes)
    f.write(struct.pack(_FILESIZE_FMT, original_size))


def read_header_plain(f: BinaryIO) -> tuple[str, int]:
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


# --- encryption helpers ---------------------------------------
def _derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password)


def _encrypt_all(name_bytes: bytes, data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    name_ct = aesgcm.encrypt(nonce, name_bytes, None)
    data_ct = aesgcm.encrypt(nonce, data, None)
    return nonce, name_ct, data_ct


def _decrypt_all(name_ct: bytes, data_ct: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    name = aesgcm.decrypt(nonce, name_ct, None)
    data = aesgcm.decrypt(nonce, data_ct, None)
    return name, data


def write_header_encrypted(
    f: BinaryIO, original_name: str, data: bytes, mode: bytes, password: bytes | None
) -> None:
    if AESGCM is None:
        raise RuntimeError("cryptography dependency is required for encrypted .bruh files")

    name_bytes = original_name.encode("utf-8")
    # PR mode: derive key from password + random salt
    if mode == ENC_PR:
        salt = os.urandom(16)
        key = _derive_key_from_password(password or b"", salt)
    else:  # ENC_PU
        salt = b""
        key = _BUILTIN_KEY

    nonce, name_ct, data_ct = _encrypt_all(name_bytes, data, key)

    f.write(BRUH_MAGIC)
    f.write(mode)
    # salt length (1 byte) + salt
    f.write(struct.pack(">B", len(salt)))
    if salt:
        f.write(salt)
    # nonce length (1) + nonce
    f.write(struct.pack(">B", len(nonce)))
    f.write(nonce)
    # lengths for ciphertexts
    f.write(_pack_u32(len(name_ct)))
    f.write(struct.pack(_FILESIZE_FMT, len(data_ct)))
    f.write(name_ct)
    f.write(data_ct)


def read_header_encrypted(f: BinaryIO) -> tuple[bytes, bytes, bytes]:
    if AESGCM is None:
        raise RuntimeError("cryptography dependency is required for encrypted .bruh files")

    raw = f.read(1)
    if len(raw) != 1:
        raise ValueError("Unexpected EOF while reading salt length")
    (salt_len,) = struct.unpack(">B", raw)
    salt = f.read(salt_len) if salt_len else b""

    raw = f.read(1)
    if len(raw) != 1:
        raise ValueError("Unexpected EOF while reading nonce length")
    (nonce_len,) = struct.unpack(">B", raw)
    nonce = f.read(nonce_len)
    if len(nonce) != nonce_len:
        raise ValueError("Unexpected EOF while reading nonce")

    raw = f.read(4)
    if len(raw) != 4:
        raise ValueError("Unexpected EOF while reading name ciphertext length")
    name_ct_len = _unpack_u32(raw)

    raw = f.read(struct.calcsize(_FILESIZE_FMT))
    if len(raw) != struct.calcsize(_FILESIZE_FMT):
        raise ValueError("Unexpected EOF while reading data ciphertext length")
    (data_ct_len,) = struct.unpack(_FILESIZE_FMT, raw)

    name_ct = f.read(name_ct_len)
    if len(name_ct) != name_ct_len:
        raise ValueError("Unexpected EOF while reading name ciphertext")

    data_ct = f.read(data_ct_len)
    if len(data_ct) != data_ct_len:
        raise ValueError("Unexpected EOF while reading data ciphertext")

    return salt, nonce, name_ct, data_ct


# --- bruh functions --------------------------------------------
def pack_file(input_path: Path, output_path: Path) -> None:
    logger.info("reading file data from %s", input_path)
    data = input_path.read_bytes()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("creating bruh file at %s", output_path)

    with output_path.open("wb") as f:
        # Ask user for encryption choice
        print("Encryption options: (N)one, (P)U built-in, (R) user-provided")
        choice = input("Choose encryption [N/P/R]: ").strip().upper()
        if choice == "R":
            if AESGCM is None:
                raise RuntimeError("cryptography package required for PR mode")
            pw = getpass.getpass("Enter encryption password: ").encode("utf-8")
            write_header_encrypted(f, input_path.name, data, ENC_PR, pw)
        elif choice == "P":
            if AESGCM is None:
                raise RuntimeError("cryptography package required for PU mode")
            write_header_encrypted(f, input_path.name, data, ENC_PU, None)
        else:
            write_header_plain(f, input_path.name, len(data))
            f.write(data)


def unpack_file(bruh_path: Path, output_dir: Path) -> Path:
    logger.info("reading bruh file from %s", bruh_path)

    if not bruh_path.is_file():
        raise FileNotFoundError(f".bruh not found: {bruh_path}")

    with bruh_path.open("rb") as f:
        magic = f.read(len(BRUH_MAGIC))
        if magic != BRUH_MAGIC:
            raise ValueError("Not a v0.3 .bruh file (bad magic)")

        enc_mode = f.read(1)
        if enc_mode == ENC_NONE:
            filename, filesize = read_header_plain(f)
            logger.info("found file %s (%s bytes)", filename, filesize)
            data = f.read(filesize)
        elif enc_mode in (ENC_PU, ENC_PR):
            salt, nonce, name_ct, data_ct = read_header_encrypted(f)
            logger.info("found encrypted file (mode=%s)", enc_mode)
            if enc_mode == ENC_PR:
                pw = getpass.getpass("Enter decryption password: ").encode("utf-8")
                key = _derive_key_from_password(pw, salt)
            else:
                key = _BUILTIN_KEY

            name_bytes, data = _decrypt_all(name_ct, data_ct, key, nonce)
            filename = name_bytes.decode("utf-8")
            filesize = len(data)
            logger.info("decrypted file %s (%s bytes)", filename, filesize)
        else:
            raise ValueError("Unknown encryption mode in .bruh file")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    output_path.write_bytes(data)
    return output_path


# --- main program (simple interactive UI) ----------------------
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
            if out_path.exists() and out_path.is_dir():
                out_path = out_path / (inp.name + ".bruh")
                print(f"Output is a directory — using {out_path}")
            try:
                print("Packing...")
                pack_file(inp, out_path)
                logger.info("packed successfully")
            except Exception as e:
                logger.error("pack failed: %s", e)

        elif choice == "u":
            bruh = prompt_path("Path of .bruh file to unpack: ")
            outdir = input("Output directory (ENTER for current folder): ").strip()
            outdir_path = Path(outdir) if outdir else Path.cwd()
            if outdir_path.exists() and outdir_path.is_file():
                print(f"Provided output is a file — using its parent directory {outdir_path.parent}")
                outdir_path = outdir_path.parent
            try:
                print("Unpacking...")
                restored = unpack_file(bruh, outdir_path)
                logger.info("restored: %s", restored)
            except Exception as e:
                logger.error("unpack failed: %s", e)
        else:
            print("Invalid option — enter 'p', 'u', or 'q'.")


if __name__ == "__main__":
    main()
