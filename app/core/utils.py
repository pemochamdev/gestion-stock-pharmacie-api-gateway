# ============= Utilitaires de sécurité =============

from core import config
from argon2 import PasswordHasher
import jwt
import uuid


# Utiliser Argon2id pour un hachage de mot de passe très sécurisé
password_hasher = PasswordHasher(
    time_cost=3,       # Nombre d'itérations
    memory_cost=65536,  # Utilisation de la mémoire en KiB (64 MB)
    parallelism=4,     # Niveau de parallélisme
    hash_len=32,       # Longueur de la sortie
    salt_len=16        # Longueur du sel
)


def get_db():
    """Fournit une session de base de données et assure sa fermeture après utilisation"""
    db = config.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Générer un JWT sécurisé
def create_access_token(data: dict, expires_delta: timedelta) -> str:
    """Crée un token JWT avec les informations de l'utilisateur et un identifiant unique"""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    issued_at = datetime.utcnow()
    jti = str(uuid.uuid4())  # Identifiant unique de token
    
    to_encode.update({
        "exp": expire,
        "iat": issued_at,
        "jti": jti
    })
    
    encoded_jwt = jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return encoded_jwt, jti, expire