import os
import getpass 
import argparse
import struct 

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"AESGCM01"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERATIONS = 200000
KEY_LEN = 32 

def derive_key (password: str, salt: bytes, iterations: int) -> bytes:
     """
    Avleder en symmetrisk nøkkel fra et passord ved hjelp av PBKDF2-HMAC-SHA256.

    password: passordet brukeren skriver inn (tekst)
    salt: tilfeldig salt (bytes)
    iterations: antall iterasjoner i PBKDF2 (int)
    return: 32 bytes nøkkel (for AES-256)
    """


