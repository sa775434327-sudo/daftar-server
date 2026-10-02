from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone
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


# =========================
# Database
# =========================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


# =========================
# Users table
# =========================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(300), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


# =========================
# Sessions table
# =========================

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    token = Column(String(200), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


Base.metadata.create_all(bind=engine)


# =========================
# Password functions
# =========================

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000,
    )

    return (
        "pbkdf2_sha256$200000$"
        + salt.hex()
        + "$"
        + password_hash.hex()
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, hash_hex = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        salt = bytes.fromhex(salt_hex)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )

        return secrets.compare_digest(
            calculated.hex(),
            hash_hex,
        )

    except Exception:
        return False


# =========================
# Request models
# =========================

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


# =========================
# Basic endpoints
# =========================

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


# =========================
# Login
# =========================

@app.post("/login")
def login(data: LoginRequest):

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.username == data.username)
            .first()
        )

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="اسم المستخدم أو كلمة المرور غير صحيحة"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="الحساب غير مفعل"
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
            token=token,
            created_at=datetime.now(timezone.utc),
        )

        db.add(new_session)
        db.commit()

        return {
            "status": "ok",
            "token": token,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
            }
        }

    finally:
        db.close()


# =========================
# Create first manager
# =========================

@app.post("/setup-manager")
def setup_manager(data: CreateUserRequest):

    db = SessionLocal()

    try:
        existing_manager = (
            db.query(User)
            .filter(User.role == "manager")
            .first()
        )

        if existing_manager:
            raise HTTPException(
                status_code=409,
                detail="تم إنشاء المدير مسبقًا"
            )

        existing_user = (
            db.query(User)
            .filter(User.username == data.username)
            .first()
        )

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="اسم المستخدم موجود مسبقًا"
            )

        manager = User(
            username=data.username,
            password_hash=hash_password(data.password),
            role="manager",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        db.add(manager)
        db.commit()
        db.refresh(manager)

        return {
            "status": "ok",
            "message": "تم إنشاء حساب المدير",
            "user": {
                "id": manager.id,
                "username": manager.username,
                "role": manager.role,
            }
        }

    finally:
        db.close()


# =========================
# Create user
# =========================

@app.post("/users")
def create_user(
    data: CreateUserRequest,
    token: str
):

    db = SessionLocal()

    try:
        session = (
            db.query(Session)
            .filter(Session.token == token)
            .first()
        )

        if session is None:
            raise HTTPException(
                status_code=401,
                detail="جلسة الدخول غير صحيحة"
            )

        manager = (
            db.query(User)
            .filter(User.id == session.user_id)
            .first()
        )

        if manager is None or manager.role != "manager":
            raise HTTPException(
                status_code=403,
                detail="هذه العملية للمدير فقط"
            )

        if data.role not in ["user", "manager"]:
            raise HTTPException(
                status_code=400,
                detail="الدور غير صحيح"
            )

        existing = (
            db.query(User)
            .filter(User.username == data.username)
            .first()
        )

        if existing:
            raise HTTPException(
                status_code=409,
                detail="اسم المستخدم موجود مسبقًا"
            )

        user = User(
            username=data.username,
            password_hash=hash_password(data.password),
            role=data.role,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "status": "ok",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
            }
        }

    finally:
        db.close()
