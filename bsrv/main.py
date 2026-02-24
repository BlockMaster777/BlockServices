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
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("api.log", encoding="utf-8"),
                        logging.StreamHandler()
                        ])
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = fastapi.FastAPI(title="BlockServices")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"]
)

security = HTTPBearer()

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20, pattern="^[a-zA-Z0-9_]+$")
    name: str = Field(min_length=1, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    email: str = Field(pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password: str = Field(min_length=8, max_length=100)

class UserLogin(BaseModel):
    username: str
    password: str


async def get_current_user(credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)) ->  int:
    credentials_exception = fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
            )
    try:
        uid = lg.get_uid_from_token(credentials.credentials, SECRET_KEY)
        if uid is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    return uid


@app.get("/")
async def root():
    return {"message": "Hello World", "status": "ok"}


@app.post("/dash/auth/register")
async def register(user: UserCreate):
    logger.log(1, f"Register start {user.username}, {user.name}, {user.email}, {user.password}", exc_info=True)
    try:
        uid = lg.register_user(user.password, user.username, user.name, user.email)
    except UserAlreadyExists:
        raise fastapi.HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        raise fastapi.HTTPException(status_code=400, detail=str(e))
    return {"uid": uid}

@app.post("/dash/auth/login")
async def login(user: UserLogin):
    if lg.check_password(user.password, user.username):
        try:
            uid = lg.get_user_id(user.username)
        except UserDoesntExist:
            raise fastapi.HTTPException(status_code=400, detail="User doesn't exist")
        access_token = lg.create_access_token({"uid": uid}, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY)
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise fastapi.HTTPException(status_code=400, detail="Incorrect username or password")

@app.post("/dash/auth/whoami")
async def whoami(credentials: HTTPAuthorizationCredentials = fastapi.Depends(security)):
    try:
        uid = await get_current_user(credentials)
    except InvalidTokenError:
        raise fastapi.HTTPException(status_code=400, detail="Incorrect username or password")
    return {"username": uid}
