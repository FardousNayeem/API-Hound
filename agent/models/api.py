from typing import Optional
from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Returned by GET /users/me — includes private fields.
class UserPrivate(BaseModel):
    id: int
    username: str
    email: str
    role: str
    age: Optional[int] = None
    bio: Optional[str] = None

# Returned by GET /users/{user_id} — public fields only.
class UserPublic(BaseModel):
    id: int
    username: str
    bio: Optional[str] = None


class CommentResponse(BaseModel):
    id: int
    post_id: int
    author_id: int
    body: str
