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
    Derieves a symmetric key from a password with the help of PBKDF2-HMAC-SHA256.
    
    password: the password which the user chooses (input)
    salt: random salt (bytes)
    iterations: number of iterations in PBKDF2 (int)
    return: 32 bytes key (for AES-256)
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
          raise ValueError(f"Unsupported version: {version}. Expected {VERSION}")
     
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

     ciphertext = blob[offset:]
     key = derive_key(password=password, salt=salt, iterations=iterations)
     aesgcm = AESGCM(key)
     associated_data = None

     plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=associated_data)
     out_path.write_bytes(plaintext)
     
def build_cli_parser() -> argparse.ArgumentParser:
    """
    Making a CLI-parser (argparse) with two commandoes: encrypt and decrypt
    """
    parser = argparse.ArgumentParser(
        description="AES-GCM file encryption/decryption using password-based key derivation (PBKDF2)."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--in", dest="in_file", required=True, help="Input file path")
    p_enc.add_argument("--out", dest="out_file", required=True, help="Output encrypted file path")

    p_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--in", dest="in_file", required=True, help="Input encrypted file path")
    p_dec.add_argument("--out", dest="out_file", required=True, help="Output decrypted file path")

    return parser

def main() -> None:
    """
    The entry point: python aes_file.py ...
    """
    parser = build_cli_parser()
    args = parser.parse_args()

    in_path = Path(args.in_file)
    out_path = Path(args.out_file)

    password = getpass.getpass("Password: ")

    if args.command == "encrypt":
        encrypt_file(in_path=in_path, out_path=out_path, password=password)
        print(f"Encrypted: {in_path} -> {out_path}")
    elif args.command == "decrypt":
        decrypt_file(in_path=in_path, out_path=out_path, password=password)
        print(f"Decrypted: {in_path} -> {out_path}")

if __name__ == "__main__":
    main()




