import os
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import redis



SERVICES = {
    "medicament": os.getenv("MEDICAMENT_SERVICE_URL", "http://medicament:8001"),
    "fournisseurs": os.getenv("FOURNISSEURS_SERVICE_URL", "http://fournisseurs:8002"),
    "ventes": os.getenv("VENTES_SERVICE_URL", "http://ventes:8003"),
    "utilisateurs": os.getenv("UTILISATEURS_SERVICE_URL", "http://utilisateurs:8004"),
    "rapport": os.getenv("RAPPORT_SERVICE_URL", "http://rapport:8005"),
}



# ============= Configuration sécurisée =============
# Utiliser des variables d'environnement pour toutes les valeurs sensibles
# avec valeurs par défaut pour le développement uniquement
SECRET_KEY = os.environ.get("SECRET_KEY", None)
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

# Clé secondaire pour le chiffrement des données sensibles en base
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", None)
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable is required")

# Configuration de la base de données
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", None)
if not DB_PASSWORD:
    raise ValueError("DB_PASSWORD environment variable is required")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "gateway_db")

# Temps d'expiration des tokens
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Algorithme JWT sécurisé

ALGORITHM = os.environ.get("ALGORITHM", "gateway_db")

# Configuration Redis pour le rate limiting et la gestion des tokens révoqués
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

# Limites de taux par défaut
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_PER_HOUR = int(os.environ.get("RATE_LIMIT_PER_HOUR", "1000"))

# Configuration des services
SERVICE_REGISTRY = {
    "users": os.environ.get("USERS_SERVICE_URL", "http://user-service:8001"),
    "products": os.environ.get("PRODUCTS_SERVICE_URL", "http://product-service:8002"),
    "orders": os.environ.get("ORDERS_SERVICE_URL", "http://order-service:8003"),
}

# Configuration sécurité stricte
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_MINUTES = 30
MFA_REQUIRED = True


# ============= Initialisation de Redis =============
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    password=REDIS_PASSWORD,
    decode_responses=True,
    ssl=True if os.environ.get("REDIS_SSL", "false").lower() == "true" else False
)

# ============= Configuration de la base de données =============
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Créer une connexion sécurisée à la base de données
engine = sa.create_engine(
    DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,  # Recycler les connexions après 30 minutes
    connect_args={
        "sslmode": "require",  # Forcer SSL
        "application_name": "api_gateway"  # Identifier les connexions
    }
)

# Créer une session pour interagir avec la base de données
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
