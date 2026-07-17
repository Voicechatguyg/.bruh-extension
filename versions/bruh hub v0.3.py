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