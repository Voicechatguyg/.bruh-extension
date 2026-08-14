"""
bruh hub - v0.4
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

from fileinput import filename
from getpass import getpass
import logging
import os
import struct
import textwrap

from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
#--- version --------------------------------------------------------------------------------

# v0.4:
# - gonna add optional usage of a hardcoded encryption key
#   to stop curious people (who dont have bruh hub) from opening it.
#   this will be done by: asking what type of encryption (public/private),
#   storing them as 00x0 or 01x0 in the header
#   when person 2 tries to unpack, the program detects the encryption type in the header (1 byte)
#   when the program detects it, they will either ask for password or use the hardcoded key.
#   NOTE: yes this is how its gonna be. its mainly to stop curious people from opening it, (probably dont have bruh hub)
#         this is also a choice, with a warning that anyone with the software will be able to open it.
#   NOTE 2 (VERY IMPORTANT): this is NOT asymmetric cryptography
# --- constants -------------------------------------------------------------

BRUH_MAGIC = b"BRUH"
VERSION = b"v0.4"

SUPPORTED_VERSIONS = (
    b"v0.1",
    b"v0.2",
    b"v0.3",
    b"v0.4",
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

PUBLIC_KEY = bytes.fromhex(
    "6d7151288bcdc112387dc41c88da3462033923815b0872d2d4942ec479b9f512"
)

if len(PUBLIC_KEY) != KEY_SIZE:
    raise RuntimeError("invalid public key length,\n" 
        "your version of bruh hub is probably broken,\n" 
        "please reinstall it from the official github page:\n" 
        "<https://github.com/Voicechatguyg/.bruh-extension>\n" 
        "(how the hell did you manage to break this bro)"
    )

# --- TUI prompts -------------------------------------------------------------------
PROMPT_START = textwrap.dedent("""
bruh hub v0.4
────────────────────────────

What do you want to do?

[P] Pack
[U] Unpack
[Q] Quit

Choice:
> """)


PROMPT_PACK_PATH = textwrap.dedent("""
bruh hub v0.4
────────────────────────────

Pack

Enter the path of the file you want to pack.

Path:
> """)

PROMPT_PACK_OUTPUT = textwrap.dedent("""
bruh hub v0.4
────────────────────────────

Pack

Enter the output path for the .bruh file.

Output path:
> """)

PACK_ENCRYPTION_TYPE_PROMPT = textwrap.dedent("""
bruh hub v0.4
────────────────────────────
Pack

What type of encryption do you want to use?

[public] Public (anyone with bruh hub can decrypt)
[private] Private (requires a password to decrypt)
[h] Help (more information about encryption types)
[c] Cancel (go back to main menu)

Choice:
> """)

PACK_ENCRYPTION_TYPE_HELP = textwrap.dedent("""
bruh hub v0.4
────────────────────────────
Pack


Encryption Types Help


Public:
    - Anyone with bruh hub can decrypt the file.
    - Does not require a password.
    - Uses a key built into bruh hub.
    - Not recommended for sensitive data.

Private:
    - Requires a password to decrypt the file.
    - Uses a key derived from the password.
    - Password is chosen by the user.
    - Recommended for sensitive data.


Press ENTER to return.
""")

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
        bruh hub v0.4
        Copyright (C) 2026 YourLocalPotato

        Licensed under GNU General Public License v3.0 (GPLv3).
        Free software: use, study, modify, and redistribute.

        NO WARRANTY.
        See LICENSE/README for details.
        https://www.gnu.org/licenses/gpl-3.0.html

        Press ENTER to continue.
    """)
    input(LICENSE_TEXT)

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

def peek_encryption_type(bruh_path: Path) -> int:
    """Read just the encryption type from the .bruh header."""
    with bruh_path.open("rb") as f:
        # Read magic (4 bytes)
        magic = f.read(4)
        if magic != BRUH_MAGIC:
            raise ValueError("Not a .bruh file")
        
        # Read version (4 bytes)
        version = f.read(4)
        if version not in SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported version: {version}")
        
        # Read the single encryption type byte
        raw = f.read(1)
        if len(raw) != 1:
            raise ValueError("Truncated header: missing encryption type")
        
        return raw[0]  # Returns 0x00 for public, 0x01 for private


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
    encryption_type: int,
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
            encryption_type,
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
    password: str | None
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

        if encryption_type == ENCRYPTION_PRIVATE:
            if password is None:
                raise ValueError(
                    "password is required for private mode"
                )
            key = derive_key(
                password,
                salt
            )
        elif encryption_type == ENCRYPTION_PUBLIC:
            key = PUBLIC_KEY
        else:
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

        safe_name = Path(filename).name
        if Path(filename).is_absolute() or ".." in Path(filename).parts:
            raise ValueError("Malicious filename detected: path traversal attempt")
        output_path = output_dir / safe_name
        output_path.write_bytes(file_data)  

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

    safe_name = Path(filename).name
    if Path(filename).is_absolute() or ".." in Path(filename).parts:
        raise ValueError("Malicious filename detected: path traversal attempt")
    output_path = output_dir / safe_name
    output_path.write_bytes(data)  

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
        password = getpass(
            "Enter encryption password: "
        ).strip()

        if not password:
            print("Password cannot be empty.")
            continue

        return password


def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


# --- main program ----------------------------------------------

def main() -> None:
    print_startup_banner()

    while True:
        choice = input(PROMPT_START).strip().lower()

        if choice in ("q", "quit"):
            print("Bye")
            return

        elif choice in ("p", "pack"):

            clear_screen()

            inp = prompt_path(PROMPT_PACK_PATH)


            default_out = inp.with_suffix(
                inp.suffix + ".bruh"
            )


            out = input(PROMPT_PACK_OUTPUT).strip()


            out_path = (
                Path(out)
                if out
                else default_out
            )


            if out_path.exists() and out_path.is_dir():
                out_path = out_path / (
                    inp.name + ".bruh"
                )


            while True:
                encryption_type = input(PACK_ENCRYPTION_TYPE_PROMPT).strip().lower()

                if encryption_type == "h":
                    print(PACK_ENCRYPTION_TYPE_HELP)
                    continue

                elif encryption_type == "c":
                    print("Cancelling pack operation.")
                    break

                elif encryption_type not in ("public", "private"):
                    print("Invalid option — enter 'public', 'private', 'h', or 'c'.")
                    continue

            if encryption_type == "c":
                continue  # Go back to main menu

            if encryption_type == "public":
                warning_string = textwrap.dedent(
                    """⚠ PUBLIC MODE WARNING
                    This does NOT use public-key/asymmetric cryptography.
                    The encryption key is built into bruh hub.
                    Anyone who has a copy of bruh hub can potentially extract this key
                    and decrypt files created in public mode.
                    Do NOT use public mode for sensitive or private data.
                    do you want to continue? (y/n)
                """)
                continue_state = input(warning_string)
                if continue_state.strip().lower() not in ("y", "yes"):
                    print("aborting...")
                    continue
                else:
                    last_warning_string = textwrap.dedent("""[last warning blablabla ts is a placeholder for now]
                    type "i understand" to continue, or anything else to abort
                    """)
                    last_warning_continue_state = input(last_warning_string)
                    if last_warning_continue_state.strip().lower() != "i understand":
                        print("aborting...")
                        continue

                encryption_type_value = ENCRYPTION_PUBLIC
                password = None
                salt = os.urandom(
                    SALT_SIZE
                )
                key = PUBLIC_KEY

                print("Packing...")

                pack_file(
                    inp,
                    out_path,
                    encryption_type_value,
                    key,
                    salt
                )

                logger.info(
                    "packed successfully: %s",
                    out_path
                )

            elif encryption_type == "private":
                encryption_type_value = ENCRYPTION_PRIVATE
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
                    encryption_type_value,
                    key,
                    salt
                )

                logger.info(
                    "packed successfully: %s",
                    out_path
                )



        elif choice in ("u", "unpack"):

            clear_screen()

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
                if not bruh.exists() or not bruh.is_file():
                    raise FileNotFoundError(
                        f".bruh file not found: {bruh}"
                    )

                encryption_type = peek_encryption_type(
                    bruh
                )
                if encryption_type == ENCRYPTION_PRIVATE:
                    password = prompt_password()
                elif encryption_type == ENCRYPTION_PUBLIC:
                    password = None
                else:
                    raise ValueError(
                        "unsupported encryption type"
                    )


                if not bruh.exists() or not bruh.is_file():
                    raise FileNotFoundError(
                        "bro stop trolling me."
                    )

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
