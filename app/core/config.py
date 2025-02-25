import os

SERVICES = {
    "medicament": os.getenv("MEDICAMENT_SERVICE_URL", "http://medicament:8001"),
    "fournisseurs": os.getenv("FOURNISSEURS_SERVICE_URL", "http://fournisseurs:8002"),
    "ventes": os.getenv("VENTES_SERVICE_URL", "http://ventes:8003"),
    "utilisateurs": os.getenv("UTILISATEURS_SERVICE_URL", "http://utilisateurs:8004"),
    "rapport": os.getenv("RAPPORT_SERVICE_URL", "http://rapport:8005"),
}
