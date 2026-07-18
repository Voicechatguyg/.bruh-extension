"""
bruh hub v0.3
Copyright (C) 2026 YourLocalPotato

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""

#--- imports -------------------------------------------------------------------

from __future__ import annotations

import logging
import os
import struct

from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# --- version ------------------------------------------------------------------

# v0.3.5:
# - added backwards compatibility with legacy .bruh files (bruh v0.1 and v0.2)

# --- constants -------------------------------------------------------------

BRUH_MAGIC = b"BRUH"
VERSION = b"v0.3"

SUPPORTED_VERSIONS = (
    b"v0.1",
    b"v0.2",
    b"v0.3",
)

LEGACY_VERSIONS = (
    b"v0.1",
    b"v0.2",
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


ENCRYPTION_PUBLIC = 0x00
ENCRYPTION_PRIVATE = 0x01

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
    print(".bruh hub v0.3")
    print("Copyright (C) 2026 YourLocalPotato")
    print()
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under certain conditions.")
    print()


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

def read_legacy_header(f: BinaryIO) -> tuple[str, int]:
    magic = f.read(len(BRUH_MAGIC))

    if magic != BRUH_MAGIC:
        raise ValueError("Not a .bruh file (bad magic)")

    version = f.read(len(VERSION))

    if version not in LEGACY_VERSIONS:
        raise ValueError(f"Unsupported .bruh version: {version.decode('utf-8')}")
    else:
        pass # Version is supported; [PROCEED] with reading the header
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


def detect_version(bruh_path: Path) -> bytes:
    with bruh_path.open("rb") as f:
        magic = f.read(len(BRUH_MAGIC))

        if magic != BRUH_MAGIC:
            raise ValueError(
                "Not a .bruh file (bad magic)"
            )

        version = f.read(len(VERSION))

        if len(version) != len(VERSION):
            raise ValueError(
                "Unexpected EOF while reading version"
            )

        return version


def unpack_file(
    bruh_path: Path,
    output_dir: Path,
    password: str
) -> Path:
    """
    Decrypt and extract a .bruh file.
    """

    version = detect_version(bruh_path)

    if version in LEGACY_VERSIONS:
        restored = unpack_legacy_file(
            bruh_path,
            output_dir
        )

        return restored

    elif version == VERSION:
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
        key = derive_key(
    password,
    salt
)

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

    else:
        raise ValueError(
            f"Unsupported .bruh version: {version.decode('utf-8')}"
        )

def unpack_legacy_file(
    bruh_path: Path,
    output_dir: Path,
) -> Path:
    logger.info("reading bruh file from %s", bruh_path)

    if not bruh_path.is_file():
        raise FileNotFoundError(f".bruh not found: {bruh_path}")

    with bruh_path.open("rb") as f:
        filename, filesize = read_legacy_header(f)

        logger.info("found file %s (%s bytes)", filename, filesize)

        data = f.read(filesize)

    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / filename

    output_path.write_bytes(data)

    return output_path

#--- CLI -------------------------------------------------------------------
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

                restored = unpack_file(
                    bruh,
                    outdir_path,
                    password
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