from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os
import hashlib
import secrets

app = FastAPI(title="Daftar Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
SETUP_KEY = os.getenv("SETUP_KEY")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL غير موجود")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

security = HTTPBearer()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    token = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )

    return salt.hex() + ":" + password_hash.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split(":")

        salt = bytes.fromhex(salt_hex)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200000
        )

        return secrets.compare_digest(
            password_hash.hex(),
            hash_hex
        )

    except Exception:
        return False


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class ResetManagerRequest(BaseModel):
    setup_key: str
    username: str
    password: str


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    db = SessionLocal()

    try:
        session = (
            db.query(Session)
            .filter(Session.token == token)
            .first()
        )

        if not session:
            raise HTTPException(
                status_code=401,
                detail="رمز الدخول غير صالح"
            )

        user = (
            db.query(User)
            .filter(User.id == session.user_id)
            .first()
        )

        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="المستخدم غير صالح أو غير نشط"
            )

        return user

    finally:
        db.close()


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "daftar-server"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/login")
def login(data: LoginRequest):
    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.username == data.username)
            .first()
        )

        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="اسم المستخدم أو كلمة المرور غير صحيحة"
            )

        if not verify_password(
            data.password,
            user.password_hash
        ):
            raise HTTPException(
                status_code=401,
                detail="اسم المستخدم أو كلمة المرور غير صحيحة"
            )

        token = secrets.token_urlsafe(48)

        new_session = Session(
            user_id=user.id,
            token=token
        )

        db.add(new_session)
        db.commit()

        return {
            "status": "ok",
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }

    finally:
        db.close()


@app.post("/setup-manager")
def setup_manager(data: LoginRequest):
    db = SessionLocal()

    try:
        existing_manager = (
            db.query(User)
            .filter(User.role == "manager")
            .first()
        )

        if existing_manager:
            raise HTTPException(
                status_code=400,
                detail="حساب المدير موجود بالفعل"
            )

        user = User(
            username=data.username,
            password_hash=hash_password(data.password),
            role="manager",
            is_active=True
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "status": "ok",
            "message": "تم إنشاء حساب المدير",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }

    finally:
        db.close()


@app.post("/reset-manager")
def reset_manager(data: ResetManagerRequest):
    if not SETUP_KEY:
        raise HTTPException(
            status_code=503,
            detail="SETUP_KEY غير مضبوط في الخادم"
        )

    if not secrets.compare_digest(
        data.setup_key,
        SETUP_KEY
    ):
        raise HTTPException(
            status_code=403,
            detail="مفتاح الإعداد غير صحيح"
        )

    db = SessionLocal()

    try:
        manager = (
            db.query(User)
            .filter(User.role == "manager")
            .first()
        )

        if not manager:
            raise HTTPException(
                status_code=404,
                detail="حساب المدير غير موجود"
            )

        manager.username = data.username
        manager.password_hash = hash_password(data.password)
        manager.is_active = True

        db.query(Session).filter(
            Session.user_id == manager.id
        ).delete()

        db.commit()

        return {
            "status": "ok",
            "message": "تم تحديث حساب المدير",
            "user": {
                "id": manager.id,
                "username": manager.username,
                "role": manager.role
            }
        }

    finally:
        db.close()


@app.post("/users")
def create_user(
    data: CreateUserRequest,
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "manager":
        raise HTTPException(
            status_code=403,
            detail="ليس لديك صلاحية إنشاء المستخدمين"
        )

    db = SessionLocal()

    try:
        existing_user = (
            db.query(User)
            .filter(User.username == data.username)
            .first()
        )

        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="اسم المستخدم موجود بالفعل"
            )

        role = data.role

        if role not in ["user", "manager"]:
            raise HTTPException(
                status_code=400,
                detail="الدور غير صالح"
            )

        user = User(
            username=data.username,
            password_hash=hash_password(data.password),
            role=role,
            is_active=True
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "status": "ok",
            "message": "تم إنشاء المستخدم",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }

    finally:
        db.close()
