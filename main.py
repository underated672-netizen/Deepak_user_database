import sqlite3
import hashlib
import secrets
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, EmailStr
import jwt

app = FastAPI(title="ARAH Mini Auth & Authz System")

SECRET_KEY = "arah_secret_key_123"
ALGORITHM = "HS256"

def get_db():
    conn = sqlite3.connect("database.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            bio TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    bio: Optional[str] = ""

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdate(BaseModel):
    name: str
    bio: Optional[str] = ""

# Secure Password Hashing (Built-in Python hashlib)
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pwd_hash}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt, pwd_hash = hashed_password.split("$")
        return hashlib.sha256((plain_password + salt).encode()).hexdigest() == pwd_hash
    except Exception:
        return False

def create_access_token(user_id: int, email: str) -> str:
    payload = {"user_id": user_id, "email": email}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_id(authorization: Optional[str] = Header(None)) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Token missing or invalid format")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["user_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or expired token")

@app.post("/register")
def register(user: UserRegister):
    hashed_pwd = hash_password(user.password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)",
            (user.email, hashed_pwd, user.name, user.bio)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {"message": "User registered successfully", "user_id": user_id}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User with this email already exists")
    finally:
        conn.close()

@app.post("/login")
def login(credentials: UserLogin):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (credentials.email,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user_id=user["id"], email=user["email"])
    return {"access_token": token, "token_type": "bearer", "message": "Login successful"}

@app.get("/profile/{user_id}")
def get_profile(user_id: int, current_user_id: int = Depends(get_current_user_id)):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="Access Denied: You can only view your own profile")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, name, bio FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return dict(user)

@app.put("/profile/{user_id}")
def update_profile(user_id: int, profile: ProfileUpdate, current_user_id: int = Depends(get_current_user_id)):
    if current_user_id != user_id:
        raise HTTPException(status_code=403, detail="Access Denied: You can only update your own profile")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET name = ?, bio = ? WHERE id = ?",
        (profile.name, profile.bio, user_id)
    )
    conn.commit()
    conn.close()

    return {"message": "Profile updated successfully"}