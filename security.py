import os
import bcrypt
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Obtener el Pepper de las variables de entorno
PEPPER = os.getenv("PEPPER", "")

def get_password_hash(password: str) -> str:
    # 1. Peppering: Concatenar el pepper a la contraseña original
    peppered_password = password + PEPPER
    
    # 2. Salting & Hashing: Generar salt y aplicar bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(peppered_password.encode('utf-8'), salt)
    
    # Devolver el hash decodificado a string para guardarlo en la base de datos
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # 1. Peppering: Concatenar el pepper a la contraseña de prueba
    peppered_password = plain_password + PEPPER
    
    # 2. Verificación: Usar checkpw que automáticamente extrae el salt del hash
    return bcrypt.checkpw(
        peppered_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )
