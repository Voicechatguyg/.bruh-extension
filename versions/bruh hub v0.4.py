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

import logging
import os
import struct

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

