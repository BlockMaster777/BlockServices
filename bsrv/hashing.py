# coding=utf-8
import hashlib


def hash_password(password) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_hash(password, hashed_password) -> bool:
    return hash_password(password) == hashed_password
