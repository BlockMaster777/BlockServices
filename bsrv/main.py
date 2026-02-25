# coding=utf-8
import os
import secrets
import fastapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
import logging
from bsrv.dbm import UserAlreadyExists, UserDoesntExist
from jwt import InvalidTokenError
from dotenv import load_dotenv
import bsrv.logic as lg

load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("api.log", encoding="utf-8"),
                        logging.StreamHandler()
                        ])
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

app = fastapi.FastAPI(title="BlockServices",
                      description="BlockServices API and alternative Scratch API for Dashblocks.",
                      version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"]
)

security = HTTPBearer()


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20, pattern="^[a-zA-Z0-9_]+$", description="Unique username")
    name: str = Field(min_length=1, max_length=50, pattern="^[a-zA-Z0-9_ ]+$", description="Display name")
    email: str = Field(pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password: str = Field(min_length=8, max_length=100)


class UserLogin(BaseModel):
    username: str = Field(description="Unique username")
    password: str


async def get_current_user(token) ->  int:
    credentials_exception = fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
            )
    try:
        uid = lg.get_uid_from_token(token, SECRET_KEY)
        if uid is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    return int(uid)


@app.get("/", summary="Test path. Returns hello message")
async def root():
    return {"message": "Hello World", "status": "ok"}


@app.post("/dash/auth/register", summary="Register new user. Needs username (unique), password, name and email. "
                                         "Returns id of new user. After that you need to get JWT token via "
                                         "logining in.")
async def register(user: UserCreate):
    logger.log(20, f"Register start {user.username}, {user.name}, {user.email}, {user.password}", exc_info=True)
    try:
        uid = lg.register_user(user.password, user.username, user.name, user.email)
    except UserAlreadyExists:
        raise fastapi.HTTPException(status_code=400, detail="User already exists")
    return {"uid": uid}


@app.post("/dash/auth/login", summary="Login into account. Needs username and password. Returns JWT token.")
async def login(user: UserLogin):
    logger.log(20, f"Login start {user.username}")
    if lg.check_password(user.password, user.username):
        try:
            uid = lg.get_user_id(user.username)
        except UserDoesntExist:
            raise fastapi.HTTPException(status_code=400, detail="User doesn't exist")
        access_token = lg.create_access_token({"uid": uid}, os.getenv("TOKEN_EXPIRE_MINUTES"), SECRET_KEY)
        logger.log(20, f"Issued JWT token for {user.username} with id {uid}")
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Incorrect username or password")


@app.get("/dash/auth/whoami", summary="Endpoint for JWT token testing. Needs JWT token in 'token' URL parameter. "
                                       "Returns the id of user from token.")
async def whoami(token: str):
    try:
        uid = await get_current_user(token)
    except InvalidTokenError:
        raise fastapi.HTTPException(status_code=400, detail="Incorrect username or password")
    return {"username": uid}


@app.get("/robots.txt")
async def robots(request: fastapi.Request):
    logger.log(20, f"Robot with ip {request.client.host}")
    return {"Content-Type": "text/plain", "body": "User-agent: *\nDisallow: /"}
