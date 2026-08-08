"""
bruh hub - v0.3
Copyright (C) 2026 YourLocalPotato

This file is part of bruh hub.

bruh hub is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

bruh hub is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with bruh hub. If not, see <https://www.gnu.org/licenses/gpl-3.0.html>
"""

#--- imports -------------------------------------------------------------------

from __future__ import annotations

import logging
import os
import struct
import textwrap

from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# --- version ------------------------------------------------------------------

# v0.3:
# - AES-256-GCM encrypted payloads
# - password based key derivation
# - (random) salts for encryption keys
# - improved payload validation

# --- constants -------------------------------------------------------------

BRUH_MAGIC = b"BRUH"
VERSION = b"v0.3"

SUPPORTED_VERSIONS = (
    b"v0.1",
    b"v0.2",
    b"v0.3",
)


# --- formats ------------------------------------------------------------------

_FILENAME_LEN_FMT = ">H"
_FILESIZE_FMT = ">Q"
_ENCRYPTION_TYPE_FMT = ">B"


# --- encryption constants -----------------------------------------------------

# sizes and values related to encryption

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600000


ENCRYPTION_PRIVATE = 0x01 # this is preperation for a change we have planned for a future version, *mysterious ambience (im so cringe help)*

# --- key derivation -----------------------------------------------------------

# functions that turn passwords into encryption keys

def derive_key(
    password: str,
    salt: bytes
) -> bytes:
    """
    Convert a password into a 32 byte AES key.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


# --- logging ------------------------------------------------------------------

def setup_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("bruh")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(levelname)s: %(message)s")
        )
        logger.addHandler(handler)

    return logger


logger = setup_logger()


# --- startup ------------------------------------------------------------------

def print_startup_banner() -> None:
    LICENSE_TEXT = textwrap.dedent("""\
        bruh hub v0.3
        Copyright (C) 2026 YourLocalPotato

        Licensed under GNU General Public License v3.0 (GPLv3).
        Free software: use, study, modify, and redistribute.

        NO WARRANTY.
        See LICENSE/README for details.
        https://www.gnu.org/licenses/gpl-3.0.html
    """)
    print(LICENSE_TEXT)


# --- header helpers -----------------------------------------------------------

"""
Write the header for a .bruh file.
structure:
magic(4)
version(4)
encryption_type(1)
salt(16)
nonce(12)
ciphertext_size(8)
ciphertext [variable]
auth_tag(16)
"""
def write_header(
    f: BinaryIO,
    encryption_type: int,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    auth_tag: bytes,
) -> None:
    
    if len(salt) != SALT_SIZE:
        raise ValueError("invalid salt size")

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

    f.write(salt)

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
) -> tuple[int, bytes, bytes, bytes, bytes]:

    magic = f.read(len(BRUH_MAGIC))

    if magic != BRUH_MAGIC:
        raise ValueError(
            "Not a .bruh file (bad magic)"
        )


    version = f.read(len(VERSION))

    if version not in SUPPORTED_VERSIONS:
        raise ValueError(
            "unsupported .bruh version"
        )


    if version != VERSION:
        raise ValueError(
            f"{version.decode()} needs an older reader"
        )


    raw = f.read(
        struct.calcsize(_ENCRYPTION_TYPE_FMT)
    )

    if len(raw) != struct.calcsize(_ENCRYPTION_TYPE_FMT):
        raise ValueError(
            "unexpected end of header"
        )


    encryption_type = struct.unpack(
        _ENCRYPTION_TYPE_FMT,
        raw
    )[0]

    salt = f.read(SALT_SIZE)

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "invalid salt"
        )
    
    nonce = f.read(NONCE_SIZE)

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "invalid nonce"
        )
    


    raw = f.read(
        struct.calcsize(_FILESIZE_FMT)
    )

    if len(raw) != struct.calcsize(_FILESIZE_FMT):
        raise ValueError(
            "unexpected end of header"
        )


    ciphertext_length = struct.unpack(
        _FILESIZE_FMT,
        raw
    )[0]


    ciphertext = f.read(ciphertext_length)

    if len(ciphertext) != ciphertext_length:
        raise ValueError(
            "unexpected end of ciphertext"
        )


    auth_tag = f.read(TAG_SIZE)

    if len(auth_tag) != TAG_SIZE:
        raise ValueError(
            "invalid authentication tag"
        )


    return (
        encryption_type,
        salt,
        nonce,
        ciphertext,
        auth_tag,
    )


# --- encryption helpers -------------------------------------------------------

def encrypt_payload(
    payload: bytes,
    key: bytes
) -> tuple[bytes, bytes, bytes]:

    if len(key) != KEY_SIZE:
        raise ValueError(
            "key must be exactly 32 bytes"
        )


    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    encrypted = aes.encrypt(
        nonce,
        payload,
        None
    )


    ciphertext = encrypted[:-TAG_SIZE]
    auth_tag = encrypted[-TAG_SIZE:]


    return (
        nonce,
        ciphertext,
        auth_tag,
    )



def decrypt_payload(
    ciphertext: bytes,
    nonce: bytes,
    auth_tag: bytes,
    key: bytes,
) -> bytes:

    if len(key) != KEY_SIZE:
        raise ValueError(
            "key must be exactly 32 bytes"
        )


    aes = AESGCM(key)

    return aes.decrypt(
        nonce,
        ciphertext + auth_tag,
        None
    )

#--- payload helpers -------------------------------------------------------------
def create_payload(input_path: Path) -> bytes:
    name_bytes = input_path.name.encode("utf-8")
    file_data = input_path.read_bytes()

    if len(name_bytes) > 0xFFFF:
        raise ValueError("filename too long")  
    
    payload = bytearray()

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

    return bytes(payload)

def read_payload(payload: bytes) -> tuple[str, bytes]:
    """
    Read payload and return filename and file data.
    """

    offset = 0

    size = struct.calcsize(_FILENAME_LEN_FMT)

    if len(payload) < size:
        raise ValueError("unexpected end of payload")


    raw = payload[offset:offset + size]

    filename_length = struct.unpack(
        _FILENAME_LEN_FMT,
        raw
    )[0]

    offset += size


    name_bytes = payload[offset:offset + filename_length]

    if len(name_bytes) != filename_length:
        raise ValueError(
            "unexpected end of payload while reading filename"
        )


    filename = name_bytes.decode("utf-8")

    offset += filename_length


    size = struct.calcsize(_FILESIZE_FMT)

    raw = payload[offset:offset + size]

    if len(raw) != size:
        raise ValueError("unexpected end of payload")


    original_size = struct.unpack(
        _FILESIZE_FMT,
        raw
    )[0]

    offset += size


    file_data = payload[offset:offset + original_size]


    if len(file_data) != original_size:
        raise ValueError(
            "unexpected end of payload while reading file data"
        )


    return filename, file_data

#--- bruh functions -------------------------------------------------------------------

def pack_file(
    input_path: Path,
    output_path: Path,
    key: bytes,
    salt: bytes
) -> None:
    """
    Create an encrypted .bruh file.
    """

    if not input_path.exists():
        raise FileNotFoundError(
            f"file not found: {input_path}"
        )

    if not input_path.is_file():
        raise ValueError(
            "input path is not a file"
        )


    payload = create_payload(
        input_path
    )

    nonce, ciphertext, auth_tag = encrypt_payload(
        payload,
        key
    )


    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )


    with output_path.open("wb") as f:
        write_header(
            f,
            ENCRYPTION_PRIVATE,
            salt,
            nonce,
            ciphertext,
            auth_tag
        )



def unpack_file(
    bruh_path: Path,
    output_dir: Path,
    key: bytes
) -> Path:
    """
    Decrypt and extract a .bruh file.
    """

    if not bruh_path.exists():
        raise FileNotFoundError(
            f".bruh file not found: {bruh_path}"
        )

    if not bruh_path.is_file():
        raise ValueError(
            "bruh path is not a file"
        )


    with bruh_path.open("rb") as f:
        (
            encryption_type,
            salt,
            nonce,
            ciphertext,
            auth_tag
        ) = read_header(f)


    if encryption_type != ENCRYPTION_PRIVATE:
        raise ValueError(
            "unsupported encryption type"
        )


    payload = decrypt_payload(
        ciphertext,
        nonce,
        auth_tag,
        key
    )


    filename, file_data = read_payload(
        payload
    )


    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )


    output_path = output_dir / filename


    output_path.write_bytes(
        file_data
    )


    return output_path

#--- TUI -------------------------------------------------------------------
# --- UI helpers ------------------------------------------------

def prompt_path(prompt: str) -> Path:
    while True:
        p = input(prompt).strip()

        if not p:
            print("Please enter a path.")
            continue

        return Path(p)
    
def prompt_password() -> str:
    while True:
        password = input(
            "Enter encryption password: "
        ).strip()

        if not password:
            print("Password cannot be empty.")
            continue

        return password


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


        elif choice in ("p", "pack"):

            inp = prompt_path(
                "Path of file to pack: "
            )


            default_out = inp.with_suffix(
                inp.suffix + ".bruh"
            )


            out = input(
                f"Output path (ENTER for {default_out}): "
            ).strip()


            out_path = (
                Path(out)
                if out
                else default_out
            )


            if out_path.exists() and out_path.is_dir():
                out_path = out_path / (
                    inp.name + ".bruh"
                )

                print(
                    f"Output is a directory — using {out_path}"
                )


            try:
                password = prompt_password()

                salt = os.urandom(
                    SALT_SIZE
                )
                
                key = derive_key(
                    password,
                    salt
                )


                print("Packing...")


                pack_file(
                    inp,
                    out_path,
                    key,
                    salt
                )


                logger.info(
                    "packed successfully: %s",
                    out_path
                )


            except Exception as e:
                logger.error(
                    "pack failed: %s",
                    e
                )



        elif choice in ("u", "unpack"):

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
                    "Output is a file, using parent directory."
                )

                outdir_path = outdir_path.parent



            try:
                password = prompt_password()

                with bruh.open("rb") as f:
                    (
                        encryption_type,
                        salt,
                        nonce,
                        ciphertext,
                        auth_tag
                    ) = read_header(f)

                key = derive_key(
                    password,
                    salt
                )

                print("Unpacking...")

                restored = unpack_file(
                    bruh,
                    outdir_path,
                    key
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