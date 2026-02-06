# A simple password vault that saves entries (crypted) in a file
# Crypting: AES-GCM, key from password via PBKDF2-HMAC-SHA256.

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"VAULT01"   # Signatur for å kjenne igjen filformatet
VERSION = 1

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password_bytes)


def _build_header(iterations: int, salt: bytes, nonce: bytes) -> bytes:
    # Header layout:
    # MAGIC (7 bytes)
    # VERSION (1 byte)
    # iterations (4 bytes, big endian)
    # salt_len (1 byte)
    # nonce_len (1 byte)
    # salt
    # nonce
    return b"".join([
        MAGIC,
        struct.pack("B", VERSION),
        struct.pack(">I", iterations),
        struct.pack("B", len(salt)),
        struct.pack("B", len(nonce)),
        salt,
        nonce,
    ])


def _parse_header(blob: bytes) -> tuple[int, bytes, bytes, int]:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a vault file (missing MAGIC).")

    offset = len(MAGIC)

    (version,) = struct.unpack_from("B", blob, offset)
    offset += 1
    if version != VERSION:
        raise ValueError(f"Unsupported vault version: {version}")

    (iterations,) = struct.unpack_from(">I", blob, offset)
    offset += 4

    (salt_len,) = struct.unpack_from("B", blob, offset)
    offset += 1
    (nonce_len,) = struct.unpack_from("B", blob, offset)
    offset += 1

    salt = blob[offset: offset + salt_len]
    offset += salt_len

    nonce = blob[offset: offset + nonce_len]
    offset += nonce_len

    return iterations, salt, nonce, offset


@dataclass
class VaultEntry:
    site: str
    username: str
    password: str
    notes: str = ""
    updated_at: float = 0.0


class Vault:
    """
    Vault saves data in this way:
    {
      "entries": {
        "<site>|<username>": { ... },
        ...
      }
    }
    and crypts the whole JSON-blob in a file.
    """

    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, Any] = {"entries": {}}

    def _entry_key(self, site: str, username: str) -> str:
        return f"{site.strip()}|{username.strip()}"

    def load(self, password: str) -> None:
        """
        Reads the vault file and decrypts it in to self.data
        If the file does not exist, it will start as an empty file
        """
        if not self.path.exists():
            self.data = {"entries": {}}
            return

        blob = self.path.read_bytes()
        iterations, salt, nonce, offset = _parse_header(blob)
        ciphertext = blob[offset:]

        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        self.data = json.loads(plaintext.decode("utf-8"))

        if "entries" not in self.data or not isinstance(self.data["entries"], dict):
            raise ValueError("Vault data is corrupted (missing entries).")

    def save(self, password: str) -> None:
        """
        Crypts the self.data and writes it to a disk 
        """
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        iterations = PBKDF2_ITERATIONS

        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)

        plaintext = json.dumps(self.data, ensure_ascii=False, indent=2).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

        header = _build_header(iterations, salt, nonce)
        self.path.write_bytes(header + ciphertext)

    def add_or_update_entry(self, site: str, username: str, password: str, notes: str = "") -> None:
        k = self._entry_key(site, username)
        now = time.time()
        self.data["entries"][k] = {
            "site": site,
            "username": username,
            "password": password,
            "notes": notes,
            "updated_at": now,
        }

    def get_entry(self, site: str, username: str) -> VaultEntry | None:
        k = self._entry_key(site, username)
        raw = self.data["entries"].get(k)
        if raw is None:
            return None
        return VaultEntry(
            site=raw["site"],
            username=raw["username"],
            password=raw["password"],
            notes=raw.get("notes", ""),
            updated_at=float(raw.get("updated_at", 0.0)),
        )

    def delete_entry(self, site: str, username: str) -> bool:
        k = self._entry_key(site, username)
        if k in self.data["entries"]:
            del self.data["entries"][k]
            return True
        return False

    def list_entries(self) -> list[tuple[str, str]]:
        """
        Returns a simple list: [(site, username), ...]
        """
        result: list[tuple[str, str]] = []
        for _, raw in self.data["entries"].items():
            result.append((raw["site"], raw["username"]))
        result.sort()
        return result

