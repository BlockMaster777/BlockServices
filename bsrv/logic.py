# coding=utf-8
import bsrv.hashing
from bsrv.dbm import *
import datetime
import jwt

dbm = DBM()

def create_access_token(data: dict, expires_time: int, secret_key: str)-> str:
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_time)
    to_encode.update({"exp": expire, "iat": datetime.datetime.now(datetime.timezone.utc), "iss": "blockservices"})
    encoded_jwt = jwt.encode(to_encode, secret_key)
    return encoded_jwt

def get_uid_from_token(token, secret_key) -> str:
    payload = jwt.decode(token, secret_key, algorithms={"HS256"}, issuer="blockservices")
    return payload["uid"]

def check_password(password: str, username: str) -> bool:
    try:
        password_in_db = dbm.get_user_psw_by_username(username)
    except UserDoesntExist:
        return False
    return bsrv.hashing.check_hash(password, password_in_db)

def register_user(password, username, name, email):
    try:
        uid = dbm.add_user(username, name, bsrv.hashing.hash_password(password), email)
    except UserAlreadyExists as e:
        raise e
    return uid

def is_admin(user_id: int) -> bool:
    return dbm.get_user(user_id)["is_admin"]
