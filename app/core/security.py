import base64
from core import config
from cryptography.fernet import Fernet
import pyotp
from datetime import datetime,timedelta
from core import config
import uuid
from typing import Optional
import secrets
from models.user import AuditLogModel,RefreshTokenModel
from sqlalchemy.orm import Session
from core import config
from core import utils
from models.user import TokenBlacklistModel,RefreshTokenModel
from argon2.exceptions import VerifyMismatchError


# Configurez l'utilitaire de cryptographie pour les données chiffrée
fernet_key = base64.urlsafe_b64encode(config.ENCRYPTION_KEY.encode()[:32].ljust(32, b'\0'))
fernet = Fernet(fernet_key)

def encrypt_data(data: str) ->str:
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str)->str:
    return fernet.decrypt(encrypted_data.encode()).decode()



def create_refresh_token(db: Session, user_id: uuid.UUID, ip_address: str, user_agent: str, device_id: str = None) -> str:
    """Crée un token de rafraîchissement et l'enregistre dans la base de données"""
    token = secrets.token_urlsafe(64)
    expires_at = datetime.utcnow() + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    
    refresh_token = RefreshTokenModel(
        token=token,
        user_id=user_id,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        device_id=device_id
    )
    
    db.add(refresh_token)
    db.commit()
    
    return token, expires_at

def generate_mfa_secret() -> str:
    """Génère un secret MFA pour TOTP"""
    return pyotp.random_base32()

def get_mfa_uri(username: str, secret: str) -> str:
    """Génère un URI pour QR code MFA"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="API Gateway Sécurisée")

def verify_mfa_code(secret: str, code: str) -> bool:
    """Vérifie le code MFA fourni"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def hash_password(password: str) -> str:
    """Hache un mot de passe avec Argon2id"""
    return utils.password_hasher.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe par rapport à son hash"""
    try:
        return utils.password_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False

def blacklist_token(db: Session, jti: str, user_id: uuid.UUID, expires_at: datetime):
    """Ajoute un token à la liste noire"""
    blacklisted_token = TokenBlacklistModel(
        token_jti=jti,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(blacklisted_token)
    db.commit()
    
    # Ajouter également à Redis pour une vérification plus rapide
    config.redis_client.setex(f"blacklist:{jti}", int((expires_at - datetime.utcnow()).total_seconds()), "1")

def is_token_blacklisted(jti: str) -> bool:
    """Vérifie si un token est sur liste noire (en utilisant Redis pour la vitesse)"""
    return bool(config.redis_client.exists(f"blacklist:{jti}"))

def log_audit(
    db: Session, 
    user_id: Optional[uuid.UUID], 
    action: str, 
    resource: str = None, 
    ip_address: str = None, 
    user_agent: str = None, 
    request_path: str = None, 
    request_method: str = None, 
    status_code: int = None, 
    details: dict = None
):
    """Enregistre une action dans le journal d'audit"""
    audit_log = AuditLogModel(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        request_path=request_path,
        request_method=request_method,
        status_code=status_code,
        details=details
    )
    
    db.add(audit_log)
    db.commit()

