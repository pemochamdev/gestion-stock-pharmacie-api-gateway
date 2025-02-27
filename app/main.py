from sqlalchemy.exc import SQLAlchemyError
from core.config import engine,Base,SessionLocal
from core.security import hash_password
from models.user import UserModel
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# ============= Initialisation de la base de données =============
def init_db():
    """Crée les tables en base de données si elles n'existent pas"""
    Base.metadata.create_all(bind=engine)
    
    # Créer un utilisateur admin par défaut si aucun n'existe
    db = SessionLocal()
    try:
        admin_exists = db.query(UserModel).filter(
            UserModel.username == "admin"
        ).first() is not None
        
        if not admin_exists:
            # Utiliser un mot de passe par défaut UNIQUEMENT si configuré dans les variables d'environnement
            admin_password = os.getenv("ADMIN_INITIAL_PASSWORD")
            if admin_password:
                admin_user = UserModel(
                    username="admin",
                    email="admin@example.com",
                    hashed_password=hash_password(admin_password),
                    full_name="Admin Initial",
                    roles=["admin", "user"],
                    require_password_change=True
                )
                db.add(admin_user)
                db.commit()
                logging.info("Utilisateur admin créé avec succès. Veuillez changer le mot de passe immédiatement.")
    except SQLAlchemyError as e:
        logging.error(f"Erreur lors de l'initialisation de la base de données: {e}")
    finally:
        db.close()

# Initialiser la base de données au démarrage
if os.getenv("AUTO_INIT_DB", "true").lower() == "true":
    init_db()

# Exécution de l'application
if __name__ == "__main__":
    import uvicorn
    
    # Configuration de la journalisation
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("api_gateway.log"),
            logging.StreamHandler()
        ]
    )
    
    # Démarrer avec des paramètres sécurisés
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=os.getenv("SSL_KEYFILE", None),
        ssl_certfile=os.getenv("SSL_CERTFILE", None),
        proxy_headers=True,
        forwarded_allow_ips='*'
    )