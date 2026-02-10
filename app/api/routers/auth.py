from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, get_current_user
from app.core.auth import create_access_token, verify_password
from app.db import crud
from app.db.models import User

router = APIRouter(tags=["auth"])


@router.post("/auth/token")
async def token(
    form: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
    user = await crud.get_user_by_username(session, form.username)
    if not user or not user.is_active or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    access_token = create_access_token(subject=str(user.id))
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/auth/me")
async def me(user: User = Depends(get_current_user)) -> dict[str, object]:
    return {"id": str(user.id), "username": user.username, "global_role": user.global_role, "is_active": user.is_active}
