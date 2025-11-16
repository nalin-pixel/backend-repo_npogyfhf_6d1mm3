import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId
from dotenv import load_dotenv

from database import db, create_document, get_documents
from schemas import User as UserSchema, Chat as ChatSchema, Message as MessageSchema

# Optional: Google token verification
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

# OpenAI
import openai

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 72

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utilities
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(subject: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = subject.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(authorization: str | None = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])  # serialize
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode error")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")


# Request models
class RegisterRequest(BaseModel):
    name: Optional[str] = None
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class GoogleAuthRequest(BaseModel):
    id_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


class ChatMessageRequest(BaseModel):
    content: str
    chat_id: Optional[str] = None


@app.get("/")
def read_root():
    return {"message": "Chatbot Backend Ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                response["collections"] = db.list_collection_names()
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:60]}"
        else:
            response["database"] = "❌ Not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:60]}"
    return response


# Auth Endpoints
@app.post("/auth/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    if db["user"].find_one({"email": req.email.lower()}):
        raise HTTPException(status_code=400, detail="Email already in use")
    user_doc = {
        "name": req.name or "",
        "email": req.email.lower(),
        "hashed_password": hash_password(req.password),
        "provider": "credentials",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted_id = db["user"].insert_one(user_doc).inserted_id
    token = create_access_token({"sub": str(inserted_id)})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email.lower()})
    if not user or not user.get("hashed_password"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)


@app.post("/auth/google", response_model=TokenResponse)
def google_auth(req: GoogleAuthRequest):
    try:
        idinfo = google_id_token.verify_oauth2_token(req.id_token, google_requests.Request())
        email = idinfo.get("email")
        sub = idinfo.get("sub")
        name = idinfo.get("name", "")
        if not email or not sub:
            raise HTTPException(status_code=400, detail="Invalid Google token")
        user = db["user"].find_one({"email": email.lower()})
        if not user:
            user_doc = {
                "name": name,
                "email": email.lower(),
                "google_id": sub,
                "provider": "google",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            inserted_id = db["user"].insert_one(user_doc).inserted_id
            user_id = str(inserted_id)
        else:
            user_id = str(user["_id"])    
        token = create_access_token({"sub": user_id})
        return TokenResponse(access_token=token)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google auth failed: {str(e)[:80]}")


@app.post("/auth/forgot")
def forgot_password(req: ForgotPasswordRequest):
    user = db["user"].find_one({"email": req.email.lower()})
    # Always return success (avoid user enumeration)
    if user:
        token = create_access_token({"sub": str(user["_id"]), "type": "reset"}, expires_delta=timedelta(minutes=30))
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"reset_token": token, "reset_expires": datetime.now(timezone.utc) + timedelta(minutes=30)}})
        # In a real app, send email with this token link
    return {"message": "If an account exists, a reset link has been created."}


@app.post("/auth/reset")
def reset_password(req: ResetPasswordRequest):
    try:
        payload = jwt.decode(req.token, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("type") != "reset":
            raise HTTPException(status_code=400, detail="Invalid reset token")
        user_id = payload.get("sub")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user or user.get("reset_token") != req.token:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"hashed_password": hash_password(req.password), "reset_token": None, "reset_expires": None, "updated_at": datetime.now(timezone.utc)}})
        return {"message": "Password updated"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


@app.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    user_copy = {k: v for k, v in user.items() if k not in ["hashed_password", "reset_token", "reset_expires"]}
    return user_copy


@app.delete("/me")
def delete_me(user: dict = Depends(get_current_user)):
    # delete user's chats and account
    db["chat"].delete_many({"user_id": str(user["_id"])})
    db["user"].delete_one({"_id": ObjectId(user["_id"])})
    return {"message": "Account deleted"}


# Chat Endpoints
@app.get("/chats")
def list_chats(user: dict = Depends(get_current_user)):
    chats = list(db["chat"].find({"user_id": str(user["_id"])}, {"messages": {"$slice": 0}}).sort("updated_at", -1))
    for c in chats:
        c["_id"] = str(c["_id"]) 
    return chats


@app.get("/chats/{chat_id}")
def get_chat(chat_id: str, user: dict = Depends(get_current_user)):
    chat = db["chat"].find_one({"_id": ObjectId(chat_id), "user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    chat["_id"] = str(chat["_id"]) 
    return chat


@app.post("/chats")
def create_chat(user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    chat_doc = ChatSchema(user_id=str(user["_id"]), title="New Chat", messages=[], created_at=now, updated_at=now).model_dump()
    inserted_id = db["chat"].insert_one(chat_doc).inserted_id
    return {"_id": str(inserted_id), **chat_doc}


@app.post("/chats/{chat_id}/message")
def send_message(chat_id: str, req: ChatMessageRequest, user: dict = Depends(get_current_user)):
    chat = db["chat"].find_one({"_id": ObjectId(chat_id), "user_id": str(user["_id"])})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    user_msg = MessageSchema(role="user", content=req.content, created_at=datetime.now(timezone.utc)).model_dump()
    messages = chat.get("messages", []) + [user_msg]

    assistant_msg = {"role": "assistant", "content": "", "created_at": datetime.now(timezone.utc)}

    # Call OpenAI if configured
    reply_text = "I couldn't reach the AI service. Please set OPENAI_API_KEY to enable replies."
    if OPENAI_API_KEY:
        try:
            # Use Chat Completions
            completion = openai.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[{"role": m["role"], "content": m["content"]} for m in messages],
                temperature=float(os.getenv("OPENAI_TEMPERATURE", "0.7"))
            )
            reply_text = completion.choices[0].message.content
        except Exception as e:
            reply_text = f"AI error: {str(e)[:200]}"

    assistant_msg["content"] = reply_text
    messages.append(assistant_msg)

    db["chat"].update_one({"_id": chat["_id"]}, {"$set": {"messages": messages, "updated_at": datetime.now(timezone.utc)}})

    return {"messages": [user_msg, assistant_msg]}
