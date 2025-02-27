from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from core.utils import get_db
from sqlalchemy.orm import Session
from core import config
import os
from models.user import UserModel
from models.schemas import TokenData
from datetime import datetime
from jose import JWTError, jwt
from typing import List
from core.security import is_token_blacklisted




# ============= Dépendances Fast API =============
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
):
    """Authentifie l'utilisateur à partir du token JWT"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les informations d'identification",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        jti: str = payload.get("jti")
        
        if user_id is None or username is None or jti is None:
            raise credentials_exception
            
        # Vérifier si le token est sur liste noire
        if is_token_blacklisted(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token révoqué",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        token_data = TokenData(**payload)
        
        # Vérifier l'expiration
        if datetime.utcnow() > token_data.exp:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
        
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    
    if user is None:
        raise credentials_exception
        
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé"
        )
        
    # Vérifier si l'utilisateur doit changer son mot de passe
    if user.require_password_change:
        # Permettre uniquement les routes de changement de mot de passe
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous devez changer votre mot de passe avant de continuer"
        )
        
    return user

async def get_current_active_user(
    current_user: UserModel = Depends(get_current_user)
):
    """Vérifie que l'utilisateur n'est pas désactivé"""
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé"
        )
    return current_user

def has_role(required_roles: List[str]):
    """Vérifie si l'utilisateur a les rôles nécessaires"""
    async def role_checker(current_user: UserModel = Depends(get_current_active_user)):
        for role in required_roles:
            if role in current_user.roles:
                return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permissions insuffisantes"
        )
    return role_checker

# Initialiser l'application FastAPI avec des paramètres sécurisés
app = FastAPI(
    title="API Gateway Sécurisée",
    description="Passerelle API hautement sécurisée pour microservices",
    version="1.0.0",
    docs_url="/documentation",  # Renommer pour éviter la détection automatique
    redoc_url=None,  # Désactiver ReDoc en production
    openapi_url="/openapi.json" if os.environ.get("ENVIRONMENT") != "production" else None
)

# ============= Middleware de sécurité =============
# CORS strictement contrôlé
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("ALLOWED_ORIGINS", "").split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Device-ID"],
    expose_headers=["X-Request-ID"],
    max_age=86400,  # 24 heures
)
