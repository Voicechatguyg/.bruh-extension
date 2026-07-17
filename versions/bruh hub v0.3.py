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
    b"v0.3"
)

_FILENAME_LEN_FMT = ">H"
_FILESIZE_FMT = ">Q"
