# coding=utf-8
import bsrv.hashing
import bcrypt
from bsrv.dbm import *
import datetime
import jwt

dbm = DBM()


async def create_access_token(data: dict, expires_time: int, secret_key: str)-> str:
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_time)
    to_encode.update({"exp": expire, "iat": datetime.datetime.now(datetime.timezone.utc), "iss": "blockservices"})
    encoded_jwt = jwt.encode(to_encode, secret_key)
    return encoded_jwt


async def get_uid_from_token(token, secret_key) -> str:
    payload = jwt.decode(token, secret_key, algorithms={"HS256"}, issuer="blockservices")
    return payload["uid"]


async def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


async def check_password(password: str, username: str) -> bool:
    try:
        password_in_db = dbm.get_user_psw_by_username(username)
    except UserDoesntExist:
        return False
    old_method = await bsrv.hashing.check_hash(password, password_in_db)
    try:
        new_method = bcrypt.checkpw(password.encode(), password_in_db.encode())
    except ValueError:
        new_method = False
    if old_method:
        print(f"old method for {username}")
        dbm.edit_password(dbm.get_user_id(username), await hash_password(password))
        return True
    if new_method:
        print(f"new method for {username}")
        return True
    return False


async def register_user(password, username, name, email):
    uid = dbm.add_user(username, name, await hash_password(password), email)
    return uid


async def is_admin(user_id: int) -> bool:
    return dbm.get_user(user_id)["is_admin"]
