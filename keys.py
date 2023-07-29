from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets
import string
def generar_clave():
    caracteres = string.ascii_letters + string.digits + string.punctuation
    longitud = 20
    clave_aleatoria = ''.join(secrets.choice(caracteres) for _ in range(longitud))
    return clave_aleatoria

def encriptar_clave(clave_maestra, clave):
    
    salt = secrets.token_bytes(16)

    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    clave_derivada = base64.urlsafe_b64encode(kdf.derive(clave_maestra.encode()))

    
    padder = sym_padding.PKCS7(128).padder()
    clave_paddeda = padder.update(clave.encode()) + padder.finalize() 
    clave_aes = clave_derivada[:32]
    iv = secrets.token_bytes(16)

    
    cipher = Cipher(algorithms.AES(clave_aes), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    clave_encriptada = encryptor.update(clave_paddeda) + encryptor.finalize()

    
    return base64.urlsafe_b64encode(salt + iv + clave_encriptada).decode()

clave_maestra = "root"  
clave = generar_clave()
clave_encriptada = encriptar_clave(clave_maestra, clave)

print("Clave generada:", clave)
print("Clave encriptada:", clave_encriptada)
