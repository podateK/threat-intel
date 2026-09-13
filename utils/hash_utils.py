from __future__ import annotations

import hashlib
import re
from typing import Optional

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
SSDEEP_HASH = re.compile(r"^\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+$")

KNOWN_MALICIOUS_HASHES: set[str] = set()


def is_valid_md5(value: str) -> bool:
    return bool(MD5_REGEX.match(value))


def is_valid_sha1(value: str) -> bool:
    return bool(SHA1_REGEX.match(value))


def is_valid_sha256(value: str) -> bool:
    return bool(SHA256_REGEX.match(value))


def is_valid_hash(value: str) -> bool:
    return is_valid_md5(value) or is_valid_sha1(value) or is_valid_sha256(value)


def detect_hash_type(value: str) -> Optional[str]:
    v = value.lower()
    if is_valid_md5(v):
        return "md5"
    if is_valid_sha1(v):
        return "sha1"
    if is_valid_sha256(v):
        return "sha256"
    return None


def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": compute_md5(data),
        "sha1": compute_sha1(data),
        "sha256": compute_sha256(data),
    }


def hash_file(path: str) -> Optional[dict[str, str]]:
    try:
        with open(path, "rb") as f:
            data = f.read()
        return compute_hashes(data)
    except (OSError, IOError):
        return None


def is_known_malicious(hash_value: str) -> bool:
    return hash_value.lower() in KNOWN_MALICIOUS_HASHES


def normalize_hash(value: str) -> str:
    return value.lower().strip()


def are_hashes_equal(h1: str, h2: str) -> bool:
    return normalize_hash(h1) == normalize_hash(h2)


def extract_hashes_from_text(text: str) -> list[str]:
    results = []
    for pattern in (MD5_REGEX, SHA1_REGEX, SHA256_REGEX):
        results.extend(m.group() for m in pattern.finditer(text))
    return list(dict.fromkeys(results))


def hash_entropy(hash_value: str) -> float:
    import math
    freq: dict[str, int] = {}
    for c in hash_value.lower():
        freq[c] = freq.get(c, 0) + 1
    length = len(hash_value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def sha256_prefix(value: str) -> str:
    return normalize_hash(value)[:8] if len(value) >= 8 else normalize_hash(value)
