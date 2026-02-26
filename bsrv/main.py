# coding=utf-8
import logging
import os
import secrets
from typing import Optional

import fastapi
import slowapi.errors
import slowapi.middleware
import slowapi.util
from dotenv import load_dotenv
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pydantic import BaseModel, Field

import bsrv.logic as lg
from bsrv.dbm import UserAlreadyExists, UserDoesntExist, ProjectDoesntExist

load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("api.log", encoding="utf-8"),
                        logging.StreamHandler()
                        ])
logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES"))

app = fastapi.FastAPI(title="BlockServices",
                      description="BlockServices API and alternative Scratch API for Dashblocks",
                      version="0.3.0",
                      docs_url="/",
                      redoc_url="/docs",
                      license_info={"name": "GPL-3.0"},
                      copyright_holder="BlockMaster777")

limiter = slowapi.Limiter(key_func=slowapi.util.get_remote_address, default_limits=["60/minute"],
                          storage_uri="memory://")

app.state.limiter = limiter
app.add_middleware(slowapi.middleware.SlowAPIMiddleware)
app.add_exception_handler(slowapi.errors.RateLimitExceeded,
                          slowapi._rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"]
)

security = HTTPBearer(auto_error=False)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20, pattern="^[a-zA-Z0-9_]+$", description="Unique username",
                          examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(min_length=1, max_length=50, pattern="^[a-zA-Z0-9_ ]+$", description="Display name",
                      examples=["User 123", "Markus Person", "DBDev - best user ever"])
    email: str = Field(pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                       examples=["dbdev@gmail.com", "vasa.belkin@yandex.ru"])
    password: str = Field(min_length=8, max_length=100)


class UserLogin(BaseModel):
    username: str = Field(description="Unique username")
    password: str


class UIDResponse(BaseModel):
    uid: int = Field(description="Unique user id", examples=[1, 2, 3])


class JWTResponse(BaseModel):
    access_token: str = Field(description="JWT token")
    token_type: str = Field(description="Token type", examples=["Bearer"])


class PublicUserData(BaseModel):
    uid: int = Field(description="Unique user id", examples=[1, 2, 3])
    username: str = Field(description="Unique username", examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(description="Display name", examples=["User 123", "Markus Person", "DBDev - best user ever"])
    is_banned: bool = Field(description="Is user banned", examples=[True, False])
    created_at: str = Field(description="Registration date")
    is_admin: bool = Field(description="Is user admin")


class UserDataResponse(BaseModel):
    id: int = Field(description="Unique user id", examples=[1, 2, 3])
    username: str = Field(description="Unique username", examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(description="Display name", examples=["User 123", "Markus Person", "DBDev - best user ever"])
    email: str = Field(description="User email", examples=["dbdev@gmail.com", "vasa.belkin@yandex.ru"])
    created_at: str = Field(description="Registration date")
    is_admin: bool = Field(description="Is user admin")
    is_banned: bool = Field(description="Is user banned")


class ProjectCreate(BaseModel):
    name: str = Field(description="Project name")
    description: str = Field(description="Project description")
    file: str = Field(description="Project file in base64 format")
    is_public: bool = Field(description="Is project public", examples=[True, False])


class ProjectData(BaseModel):
    name: str = Field(description="Project name")
    description: str = Field(description="Project description")
    author: str = Field(description="Project author")
    file: str = Field(description="Project file in base64 format")
    created_at: str = Field(description="Project creation date")
    is_public: bool = Field(description="Is project public", examples=[True, False])


async def get_current_user(token) ->  int:
    credentials_exception = fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
            )
    try:
        uid = await lg.get_uid_from_token(token, JWT_SECRET)
        if uid is None:
            print("No uid")
            raise credentials_exception
    except InvalidTokenError:
        print("Wrong token")
        raise credentials_exception
    return int(uid)


@app.post("/dash/auth/register",
          summary="Register new user",
          response_model=UIDResponse,
          responses={400: {"description": "User already exists"}}, status_code=201)
@limiter.limit("1/minute")
async def register(user: UserCreate, request: Request):
    logger.log(20, f"Register start {user.username}, {user.name}, {user.email}, {user.password}")
    try:
        uid = await lg.register_user(user.password, user.username, user.name, user.email)
    except UserAlreadyExists:
        raise fastapi.HTTPException(status_code=400, detail="User already exists")
    return UIDResponse(uid=uid)


@app.post("/dash/auth/login",
          summary="Login into account",
          response_model=JWTResponse,
          responses={400: {"description": "Incorrect username or password"}})
@limiter.limit("5/minute")
async def login(user: UserLogin, request: Request):
    logger.log(20, f"Login start {user.username}")
    if await lg.check_password(user.password, user.username):
        try:
            uid = lg.dbm.get_user_id(user.username)
        except UserDoesntExist:
            raise fastapi.HTTPException(status_code=400, detail="User doesn't exist")
        if lg.dbm.get_user(uid)["is_banned"]:
            raise fastapi.HTTPException(status_code=403, detail="You are banned")
        access_token = await lg.create_access_token({"uid": uid}, TOKEN_EXPIRE_MINUTES, JWT_SECRET)
        logger.log(20, f"Issued JWT token for {user.username} with id {uid}")
        return JWTResponse(access_token=access_token, token_type="Bearer")
    else:
        raise fastapi.HTTPException(status_code=400, detail="Incorrect username or password")


@app.get("/dash/user/{username}",  summary="Public information about user", response_model=PublicUserData)
async def get_user(username: str, request: Request):
     try:
         uid = lg.dbm.get_user_id(username)
         result = lg.dbm.get_user(uid)
     except UserDoesntExist:
         raise fastapi.HTTPException(status_code=404, detail="User doesn't exist")
     return PublicUserData(uid=result["id"], username=result["username"], name=result["name"],
                           is_banned=result["is_banned"], created_at=result["created_at"], is_admin=result["is_admin"])


@app.get("/dash/user", summary="All information about you", response_model=UserDataResponse,
         responses={400: {"description": "Incorrect token"}})
async def account(request: Request, credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        token = credentials.credentials
        uid = await get_current_user(token)
        result = lg.dbm.get_user(uid)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    return UserDataResponse(id=result["id"], username=result["username"], name=result["name"], email=result["email"],
                            created_at=result["created_at"], is_admin=result["is_admin"], is_banned=result["is_banned"])


@app.get("/dash/user/all",
         summary="List of all users. Admins only",
         response_model=list[UserDataResponse],
         responses={
             400: {"description": "Incorrect token"},
             403: {"description": "Not admin"}
             })
async def get_users(request: Request, credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        token = credentials.credentials
        is_adm = await lg.is_admin(await get_current_user(token))
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    users = lg.dbm.get_all_users()
    return [UserDataResponse(id=user["id"], username=user["username"], name=user["name"], email=user["email"],
                           is_banned=user["is_banned"], created_at=user["created_at"], is_admin=user["is_admin"])
                           for user in users]


@app.post("/dash/user/{username}/promote",
          summary="Promote a user. Admins only",
          responses={
              400: {"description": "Incorrect token"},
              403: {"description": "Not admin"},
              404: {"description": "User not found"}
              },
          status_code=201)
async def promote(username: str, credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        token = credentials.credentials
        is_adm = await lg.is_admin(await get_current_user(token))
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    try:
        await lg.promote_user(username)
    except UserDoesntExist:
        raise fastapi.HTTPException(status_code=404, detail="User doesn't exist")


@app.post(
    "/dash/user/{username}/demote",
    summary="Demote a user. Admins only",
    responses={
        400: {"description": "Incorrect token"},
        403: {"description": "Not admin"},
        404: {"description": "User not found"},
        },
    status_code=201,
)
async def demote(username: str, credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        token = credentials.credentials
        is_adm = await lg.is_admin(await get_current_user(token))
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    try:
        await lg.demote_user(username)
    except UserDoesntExist:
        raise fastapi.HTTPException(status_code=404, detail="User doesn't exist")


@app.post("/dash/project",
          summary="Upload new project to cloud",
          responses={400: {"description": "Incorrect token"}},
          status_code=201)
async def save_project(data: ProjectCreate, credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        token = credentials.credentials
        uid = await get_current_user(token)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    return await lg.load_project(uid, data.name, data.description, data.file, data.is_public)


@app.get("/dash/project/{pid}",
         summary="Get project from cloud",
         responses={
             400: {"description": "Incorrect token"},
             403: {"description": "Private project"},
             404: {"description": "Project not found"}
             },
         response_model=ProjectData)
async def get_project(pid: int, credentials: Optional[HTTPAuthorizationCredentials] = fastapi.Depends(security)):
    try:
        if credentials is None:
            uid = -1
        else:
            token = credentials.credentials
            uid = await get_current_user(token)
    except (InvalidTokenError, UserDoesntExist):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    try:
        data = await lg.get_project(pid)
    except ProjectDoesntExist:
        raise fastapi.HTTPException(status_code=404, detail="Project doesn't exist")
    if data["is_public"] or data["uid"] == uid:
        return ProjectData(name=data["name"], description=data["description"], file=data["file"],
                           author=data["author"], created_at=data["created_at"], is_public=data["is_public"])
    else:
        raise fastapi.HTTPException(status_code=403, detail="Private project")


@app.get("/robots.txt")
async def robots(request: fastapi.Request):
     logger.log(20, f"Robot with ip {request.client.host}")
     return {"Content-Type": "text/plain", "body": "User-agent: *\nDisallow: /"}
