import os
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import redis
from dotenv import load_dotenv

# Chargement du fichier .env
dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".env"))
load_dotenv(dotenv_path)

# Services microservices
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
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

# Clé secondaire pour le chiffrement des données sensibles en base
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable is required")

# Configuration de la base de données
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")
if not DB_PASSWORD:
    raise ValueError("DB_PASSWORD environment variable is required")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "gateway_db")

# Temps d'expiration des tokens
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Algorithme JWT sécurisé
ALGORITHM = os.getenv("ALGORITHM", "HS256")  # Corrigé: valeur par défaut HS256 au lieu de "gateway_db"

# Configuration Redis pour le rate limiting et la gestion des tokens révoqués
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_SSL = os.getenv("REDIS_SSL", "false").lower() == "true"

# Limites de taux par défaut
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))

# Configuration des services
SERVICE_REGISTRY = {
    "users": os.getenv("USERS_SERVICE_URL", "http://user-service:8001"),
    "products": os.getenv("PRODUCTS_SERVICE_URL", "http://product-service:8002"),
    "orders": os.getenv("ORDERS_SERVICE_URL", "http://order-service:8003"),
}

# Configuration sécurité stricte
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
PASSWORD_REQUIRE_UPPERCASE = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_LOWERCASE = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
PASSWORD_REQUIRE_DIGIT = os.getenv("PASSWORD_REQUIRE_DIGIT", "true").lower() == "true"
PASSWORD_REQUIRE_SPECIAL = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
ACCOUNT_LOCKOUT_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "30"))
MFA_REQUIRED = os.getenv("MFA_REQUIRED", "true").lower() == "true"

# ============= Initialisation de Redis =============
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=int(REDIS_PORT),
    password=REDIS_PASSWORD,
    decode_responses=True,
    ssl=REDIS_SSL
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