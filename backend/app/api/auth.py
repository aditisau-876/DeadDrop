from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import create_access_token, get_current_user, hash_password, require_roles, verify_password, generate_identifier
from app.db.database import get_db
from app.models.user import User
from app.models.trustee import Trustee
from app.schemas.auth import RegisterRequest, LoginRequest, AdminUserCreate, UserResponse, TokenResponse
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
def public_user(user: User) -> UserResponse:
    return UserResponse(id=user.id,email=user.email,full_name=user.full_name,role=user.role,is_active=user.is_active)
def token_response(user: User) -> TokenResponse:
    return TokenResponse(access_token=create_access_token(user),expires_in=settings.access_token_expire_minutes*60,user=public_user(user))
@router.post("/register",response_model=TokenResponse,status_code=201)
def register(data:RegisterRequest,db:Session=Depends(get_db)):
    if not settings.allow_public_registration:
        raise HTTPException(status_code=403,detail="Public registration is disabled.")
    email=data.email.lower().strip()
    if db.scalar(select(User).where(User.email==email)):
        raise HTTPException(status_code=409,detail="An account with this email already exists.")
    user=User(id=generate_identifier(),email=email,password_hash=hash_password(data.password),full_name=data.full_name.strip(),role="owner",is_active=True)
    db.add(user); db.commit(); db.refresh(user)
    return token_response(user)
@router.post("/login",response_model=TokenResponse)
def login(data:LoginRequest,db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==data.email.lower().strip()))
    if user is None or not user.is_active or not verify_password(data.password,user.password_hash):
        raise HTTPException(status_code=401,detail="Incorrect email or password.",headers={"WWW-Authenticate":"Bearer"})
    return token_response(user)
@router.get("/me",response_model=UserResponse)
def me(user:User=Depends(get_current_user)):
    return public_user(user)
@router.post("/admin/users",response_model=UserResponse,status_code=201)
def admin_create_user(data:AdminUserCreate,db:Session=Depends(get_db),admin:User=Depends(require_roles("admin"))):
    email=data.email.lower().strip()
    if db.scalar(select(User).where(User.email==email)):
        raise HTTPException(status_code=409,detail="An account with this email already exists.")
    if data.role=="admin" and admin.role!="admin":
        raise HTTPException(status_code=403,detail="Only an administrator can create administrators.")
    linked_trustee=None
    if data.role=="trustee":
        if not data.trustee_id: raise HTTPException(status_code=422,detail="trustee_id is required for trustee accounts.")
        linked_trustee=db.get(Trustee,data.trustee_id)
        if linked_trustee is None: raise HTTPException(status_code=404,detail="Trustee record not found.")
        if linked_trustee.user_id is not None: raise HTTPException(status_code=409,detail="This trustee is already linked to a user account.")
    elif data.trustee_id:
        raise HTTPException(status_code=422,detail="Only trustee accounts can be linked to a trustee record.")
    user=User(id=generate_identifier(),email=email,password_hash=hash_password(data.password),full_name=data.full_name.strip(),role=data.role,is_active=True)
    db.add(user)
    if linked_trustee is not None: linked_trustee.user_id=user.id
    db.commit(); db.refresh(user)
    return public_user(user)

@router.get("/admin/users",response_model=list[UserResponse])
def admin_list_users(db:Session=Depends(get_db),admin:User=Depends(require_roles("admin"))):
    return [public_user(item) for item in db.scalars(select(User).order_by(User.created_at)).all()]

@router.post("/admin/users/{user_id}/deactivate",response_model=UserResponse)
def admin_deactivate_user(user_id:str,db:Session=Depends(get_db),admin:User=Depends(require_roles("admin"))):
    if user_id == admin.id:
        raise HTTPException(status_code=400,detail="Administrators cannot deactivate their own account.")
    target=db.get(User,user_id)
    if target is None:
        raise HTTPException(status_code=404,detail="User account not found.")
    target.is_active=False
    db.commit(); db.refresh(target)
    return public_user(target)
