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
     password_bytes = password.encode("utf-8")

     kdf = PBKDF2HMAC( 
          algorithm=hashes.SHA256(),
          length= KEY_LEN,
          salt=salt,
          iterations = iterations,
          
     )

     key = kdf.derive(password_bytes)

     return key 

def encrypt_file(in_path: Path, out_path: Path, password: str) -> None:
     plaintext = in_path.read_bytes()
     salt = os.urandom(SALT_LEN)
     nonce = os.random(NONCE_LEN)
     
     key = derive_key(passwords = password, salt = salt, iterations = PBKDF2_ITERATIONS)

     aesgcm = AESGCM(key)
     associated_data = None 

     ciphertext = aesgcm.encrypt(nonce = nonce, data = plaintext, associated_data = associated_data) 
     
     header = b"".join([
        MAGIC,                              
        struct.pack("B", VERSION),          
        struct.pack(">I", PBKDF2_ITERATIONS),  
        struct.pack("B", SALT_LEN),         
        struct.pack("B", NONCE_LEN),        
        salt,                               
        nonce                               
    ])
     
def decrypt_file(in_path: Path, out_path: Path, password: str) -> None:
     
     blob = in_path.read_bytes()

     if not blob.startswith(MAGIC):
          raise ValueError("Missing MAGIC header")
     
     offset = len(MAGIC)

     (version,) = struct.unpack_from("B", blob, offset)
     offset += 1

     if version != VERSION:
          raise ValueError(f"Unsupported version: ")

     








    


