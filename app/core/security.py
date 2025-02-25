import base64
from core import config
from cryptography.fernet import Fernet



# Configurez l'utilitaire de cryptographie pour les données chiffrée
fernet_key = base64.urlsafe_b64encode(config.ENCRYPTION_KEY.encode()[:32].ljust(32, b'\0'))
fernet = Fernet(fernet_key)

def encrypt_data(data: str) ->str:
    return fernet.encrypt(data.encode()).decode


def decrypt_data(encrypted_data: str)->str:
    return fernet.decrypt(encrypted_data.encode()).decode()
