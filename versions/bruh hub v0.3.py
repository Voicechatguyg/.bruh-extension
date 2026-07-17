"""
bruh hub v0.3
Copyright (C) 2026 YourLocalPotato

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import BinaryIO
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# --- version 0.3 new features -------------------------------------------------
# new header version: v0.3
# encrypted file data using AES-256-GCM
# backwards compatibility with v0.2 and v0.1 files

# --- constants ----------------------------------------------------------------

BRUH_MAGIC = b"BRUH"  # 4 bytes
VERSION = b"v0.3"  # 4 bytes

SUPPORTED_VERSIONS = (
    b"v0.1",
    b"v0.2",
    b"v0.3",
)

_FILENAME_LEN_FMT = ">H"
_FILESIZE_FMT = ">Q"
_ENCRYPTION_TYPE_FMT = ">B"


# --- Encryption constants -----------------------------------------------------

KEY_SIZE = 32      # AES-256 key size (32 bytes = 256 bits)
NONCE_SIZE = 12    # AES-GCM nonce size (12 bytes = 96 bits)
TAG_SIZE = 16      # AES-GCM authentication tag (16 bytes = 128 bits)

ENCRYPTION_PUBLIC = 0x00
ENCRYPTION_PRIVATE = 0x01

# --- logging -------------------------------------------------------------------

def setup_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("bruh")
    logger.setLevel(level)

    if not logger.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(sh)

    return logger

logger = setup_logger()

#--- startup -------------------------------------------------------------------

def print_startup_banner() -> None:
    print(".bruh hub v0.3")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")
    print()

#--- header helpers -------------------------------------------------------------

def write_header(
    f: BinaryIO,
    encryption_type: int,
    nonce: bytes,
    ciphertext: bytes,
    auth_tag: bytes
) -> None:
    """Write the v0.3 header.

    Header layout:

    magic             4 bytes
    version           4 bytes
    encryption type   1 byte
    nonce             12 bytes
    ciphertext length 8 bytes
    ciphertext        [variable amount]
    auth tag          16 bytes

    Encrypted payload:

    filename length   2 bytes
    filename          [variable amount]
    original size     8 bytes
    file data         [variable amount]
    """

    if len(nonce) != NONCE_SIZE:
        raise ValueError("invalid nonce size")

    if len(auth_tag) != TAG_SIZE:
        raise ValueError("invalid authentication tag size")

    f.write(BRUH_MAGIC)
    f.write(VERSION)

    f.write(
        struct.pack(
            _ENCRYPTION_TYPE_FMT,
            encryption_type
        )
    )

    f.write(nonce)

    f.write(
        struct.pack(
            _FILESIZE_FMT,
            len(ciphertext)
        )
    )

    f.write(ciphertext)

    f.write(auth_tag)

def read_header(
    f: BinaryIO
) -> tuple[int, bytes, bytes, bytes]:

    magic = f.read(len(BRUH_MAGIC))

    if magic != BRUH_MAGIC:
        raise ValueError("Not a .bruh file (bad magic)")


    version = f.read(len(VERSION))

    if version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported .bruh version: {version.decode(errors='replace')}"
        )


    if version != VERSION:
        raise ValueError(
            f".bruh version {version.decode()} requires an older reader"
        )


    raw = f.read(
        struct.calcsize(_ENCRYPTION_TYPE_FMT)
    )

    encryption_type = struct.unpack(
        _ENCRYPTION_TYPE_FMT,
        raw
    )[0]


    nonce = f.read(NONCE_SIZE)

    if len(nonce) != NONCE_SIZE:
        raise ValueError("invalid nonce")


    raw = f.read(
        struct.calcsize(_FILESIZE_FMT)
    )

    ciphertext_length = struct.unpack(
        _FILESIZE_FMT,
        raw
    )[0]


    ciphertext = f.read(ciphertext_length)

    if len(ciphertext) != ciphertext_length:
        raise ValueError("unexpected end of ciphertext")


    auth_tag = f.read(TAG_SIZE)

    if len(auth_tag) != TAG_SIZE:
        raise ValueError("invalid authentication tag")


    return (
        encryption_type,
        nonce,
        ciphertext,
        auth_tag
    )


#--- encryption helpers --------------------------------------------------

def encrypt_payload(payload: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.

    Returns:
    nonce, ciphertext, authentication tag
    """

    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    encrypted = aes.encrypt(
        nonce,
        payload,
        None
    )

    ciphertext = encrypted[:-TAG_SIZE]
    auth_tag = encrypted[-TAG_SIZE:]

    return nonce, ciphertext, auth_tag

def decrypt_payload(
    ciphertext: bytes,
    nonce: bytes,
    auth_tag: bytes,
    key: bytes
) -> bytes:
    """
    Decrypt AES-256-GCM data.
    """

    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")

    aes = AESGCM(key)

    encrypted = ciphertext + auth_tag

    return aes.decrypt(
        nonce,
        encrypted,
        None
    )

#--- bruh functions -------------------------------------------------------------
def pack_file(input_path: Path) -> bytes:
    name_bytes = input_path.name.encode("utf-8")
    file_data = input_path.read_bytes()

    if len(name_bytes) > 0xFFFF:
        raise ValueError("filename too long")  
    
    payload = b""

    # filename length
    payload += struct.pack(
        _FILENAME_LEN_FMT,
        len(name_bytes)
    )

    # filename
    payload += name_bytes

    # original size
    payload += struct.pack(
        _FILESIZE_FMT,
        len(file_data)
    )

    # actual file
    payload += file_data

    return payload

