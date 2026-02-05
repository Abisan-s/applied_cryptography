from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generates a RSA private-key. 
    The public key can be obtained from the private_key.public_key() 
    key_size: 2048 is the standard, 3072/4096 is stronger but slower.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key


def save_private_key_pem(private_key: rsa.RSAPrivateKey, path: Path, password: str | None = None) -> None:
    """
    Saves the RSA privatekey to PEM. When the password is set, the PEM-file gets crypted. 
    """
    if password is None:
        encryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # vanlig, standard format
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)


def save_public_key_pem(public_key, path: Path) -> None:
    """
    This part saves the RSA public key to PEM. 
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key_pem(path: Path, password: str | None = None) -> rsa.RSAPrivateKey:
    """
    This part reads the RSA privatekey from the PEM.
    """
    data = path.read_bytes()
    key = serialization.load_pem_private_key(
        data,
        password=None if password is None else password.encode("utf-8"),
    )
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key.")
    return key


def load_public_key_pem(path: Path):
    """
    This one reads the RSA public key from PEM
    """
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    return key


if __name__ == "__main__":
    # A mini demo, can be removed if wanted 
    priv = generate_rsa_keypair(2048)
    pub = priv.public_key()

    out_dir = Path("keys")
    out_dir.mkdir(exist_ok=True)

    save_private_key_pem(priv, out_dir / "private.pem", password=None)
    save_public_key_pem(pub, out_dir / "public.pem")

    print("Saved keys to ./keys/private.pem and ./keys/public.pem")