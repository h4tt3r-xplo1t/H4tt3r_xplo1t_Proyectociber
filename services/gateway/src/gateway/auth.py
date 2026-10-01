import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from gateway.db import get_session
from gateway.models import User
from gateway.passwords import hash_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

UNIQUE_VIOLATION = "23505"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str, Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")
    ]
    # ADR 0004 decision 4: at least 15 characters and no composition rules.
    # The upper bound only limits the cost of hashing.
    password: Annotated[str, Field(min_length=15, max_length=128)]


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    body: RegisterRequest, session: Annotated[Session, Depends(get_session)]
) -> UserOut:
    user = User(username=body.username, password_hash=hash_password(body.password))
    session.add(user)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        sqlstate = getattr(exc.orig, "sqlstate", None)
        if sqlstate != UNIQUE_VIOLATION:
            # PostgreSQL's DETAIL repeats the failing row, hash included, so
            # only the SQLSTATE goes into the error that gets logged.
            raise RuntimeError(f"user insert failed (sqlstate {sqlstate})") from None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username not available"
        ) from None
    return UserOut(id=user.id, username=user.username, role=user.role)
