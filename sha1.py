import hashlib


def sha1(data: bytes):
    return hashlib.sha1(data).digest()
