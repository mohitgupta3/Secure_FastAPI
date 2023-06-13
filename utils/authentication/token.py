import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from jose import jwt
from utils.config import api_settings_config

SECRET_KEY = api_settings_config.security["private_key"]
ALGORITHM = api_settings_config.security["hash_algo"]
ACCESS_TOKEN_EXPIRE_MINUTES = api_settings_config.security[
    "access_token_expire_minutes"
]
REFRESH_TOKEN_EXPIRE_DAYS = api_settings_config.security["refresh_token_expire_days"]

PRIVATE_KEY_FILE = api_settings_config.security["private_key_file"]

# Generate or load RSA private key
if os.path.exists(PRIVATE_KEY_FILE):
    with open(PRIVATE_KEY_FILE, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(), password=None
        )
else:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIVATE_KEY_FILE, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

public_key = private_key.public_key()

# Serialize keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


# Utility function to create an access token
def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, private_pem, algorithm="RS256")


# Utility function to create a refresh token
def create_refresh_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, private_pem, algorithm="RS256")