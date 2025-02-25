# ============= Schémas Pydantic =============

from pydantic import BaseModel,EmailStr,SecretStr, validator
from datetime import datetime
from typing import List,Optional,Any
import uuid
from core import config
import re


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_at: datetime

class TokenData(BaseModel):
    sub: str  # UUID de l'utilisateur
    username: str
    roles: List[str] = []
    jti: str  # Identifiant unique pour ce token
    iat: datetime  # Timestamp de création
    exp: datetime  # Timestamp d'expiration

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: SecretStr
    
    @validator('password')
    def password_complexity(cls, v):
        password = v.get_secret_value()
        if len(password) < config.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Le mot de passe doit contenir au moins {config.PASSWORD_MIN_LENGTH} caractères")
        if config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            raise ValueError("Le mot de passe doit contenir au moins une lettre majuscule")
        if config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            raise ValueError("Le mot de passe doit contenir au moins une lettre minuscule")
        if config.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
            raise ValueError("Le mot de passe doit contenir au moins un chiffre")
        if config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError("Le mot de passe doit contenir au moins un caractère spécial")
        return v

class UserResponse(UserBase):
    id: uuid.UUID
    disabled: bool = False
    roles: List[str] = []
    mfa_enabled: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class MFASetup(BaseModel):
    secret: str
    uri: str

class MFAVerify(BaseModel):
    code: str

class LoginRequest(BaseModel):
    username: str
    password: SecretStr
    mfa_code: Optional[str] = None
    device_id: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    device_id: Optional[str] = None

class ServiceResponse(BaseModel):
    status: str
    message: str
    data: Optional[Any] = None
