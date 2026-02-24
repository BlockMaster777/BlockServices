# coding=utf-8
import hashlib
import os

def hash_password(password) -> str:
    return hashlib.sha256(hashlib.sha256(password.encode() + os.getenv("SALT").encode()).hexdigest().encode()).hexdigest()

def check_hash(password, hashed_password) -> bool:
    return hash_password(password) == hashed_password
