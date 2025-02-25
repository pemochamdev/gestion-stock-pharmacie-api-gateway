
from cryptography.fernet import Fernet
import base64
ENCRYPTION_KEY = "test"

fernet_key = base64.urlsafe_b64encode(ENCRYPTION_KEY.encode()[:32].ljust(32, b'\0'))
fernet = Fernet(fernet_key)

def encrypt_data(data: str) ->str:
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str)->str:
    return fernet.decrypt(encrypted_data.encode()).decode()


result = encrypt_data("MOHAMED")
decript = decrypt_data(result)
print(result)
print(decript)