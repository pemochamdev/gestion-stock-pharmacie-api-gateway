from sqlalchemy.orm import Session
from typing import Optional
from models.user import UserModel
from core import config
from core import utils
from core import security
from datetime import datetime,timedelta
from fastapi import HTTPException,status

def authenticate_user(db: Session, username: str, password: str) -> Optional[UserModel]:
    """Authentifie un utilisateur et gère les tentatives d'accès échouées"""
    user = db.query(UserModel).filter(UserModel.username == username).first()
    
    # Vérifier si l'utilisateur existe
    if not user:
        # Utiliser un temps fixe pour éviter les attaques temporelles
        utils.password_hasher.verify("$argon2id$v=19$m=65536,t=3,p=4$XXXXXXXXXXXXXXXX$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "dummy_password")
        return None
    
    # Vérifier si le compte est verrouillé
    now = datetime.utcnow()
    if user.account_locked_until and user.account_locked_until > now:
        # Le compte est verrouillé
        unlock_time = user.account_locked_until.strftime("%Y-%m-%d %H:%M:%S UTC")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Compte verrouillé jusqu'à {unlock_time} en raison de trop nombreuses tentatives de connexion"
        )
    
    # Vérifier le mot de passe
    if not security.verify_password(password, user.hashed_password):
        # Incrémenter le compteur de tentatives échouées
        user.failed_login_attempts += 1
        user.last_failed_login = now
        
        # Verrouiller le compte si trop de tentatives
        if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS:
            user.account_locked_until = now + timedelta(minutes=config.ACCOUNT_LOCKOUT_MINUTES)
            db.commit()
            
            # Journaliser l'événement
            security.log_audit(
                db, 
                user.id, 
                "ACCOUNT_LOCKED", 
                "user", 
                details={"reason": "Too many failed login attempts"}
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Compte verrouillé pendant {config.ACCOUNT_LOCKOUT_MINUTES} minutes en raison de trop nombreuses tentatives de connexion"
            )
        
        db.commit()
        return None
    
    # Réinitialiser le compteur de tentatives échouées
    user.failed_login_attempts = 0
    user.last_failed_login = None
    user.account_locked_until = None
    db.commit()
    
    return user
