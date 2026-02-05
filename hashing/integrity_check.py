# SHA-256 hashing + file verifying 

import hashlib
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Returns the SHA-256 hash (hex) of a file, streamed in chunks
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_hash_file(target_file: Path, hash_file: Path | None = None) -> Path:
    """
    Writes a .sha256 file which contains the hash value
    In the format "<hash> <filename>"
    """
    digest = sha256_file(target_file)
    if hash_file is None:
        hash_file = target_file.with_suffix(target_file.suffix + ".sha256")

    line = f"{digest}  {target_file.name}\n"
    hash_file.write_text(line, encoding="utf-8")
    return hash_file


def verify_hash_file(target_file: Path, hash_file: Path) -> bool:
    """
    Verifies that the target_file matches the hash value in the hash_file
    """
    content = hash_file.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError("Hash file is empty.")

    expected_hash = content.split()[0]
    actual_hash = sha256_file(target_file)
    return actual_hash == expected_hash


if __name__ == "__main__":
    # Mini-demo, can be removed if wanted
    p = Path("secret.txt")
    if p.exists():
        hf = write_hash_file(p)
        ok = verify_hash_file(p, hf)
        print("Hash file:", hf)
        print("Verified:", ok)
    else:
        print("Create a file named secret.txt to demo.")
