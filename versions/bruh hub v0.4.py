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