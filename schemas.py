"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime


class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: Optional[str] = Field(None, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    hashed_password: Optional[str] = Field(None, description="BCrypt hashed password (for email/password auth)")
    provider: Literal["credentials", "google"] = Field("credentials", description="Auth provider")
    google_id: Optional[str] = Field(None, description="Google account sub (subject) id if using Google")
    reset_token: Optional[str] = Field(None, description="Password reset token")
    reset_expires: Optional[datetime] = Field(None, description="Password reset token expiry UTC")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Message(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str
    created_at: Optional[datetime] = None


class Chat(BaseModel):
    """
    Chats collection schema
    Collection name: "chat" (lowercase of class name)
    """
    user_id: str = Field(..., description="Owner user _id as string")
    title: str = Field("New Chat", description="Chat title")
    messages: List[Message] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# Example schema kept for reference
class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    in_stock: bool = True
