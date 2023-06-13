from fastapi import Depends, APIRouter, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from utils.database import User, get_db
from utils.authentication.token import create_access_token
from utils.config import api_settings_config

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
db = get_db()

SECRET_KEY = api_settings_config.security["private_key"]
ALGORITHM = api_settings_config.security["hash_algo"]

# Route for user registration
@router.post("/register")
async def register(username: str, password: str):
    # User registration logic
    user = db.query(User).filter(User.username == username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")

    user = User(username=username, password_hash=pwd_context.hash(password))
    db.add(user)
    db.commit()

    return {"message": "Registration successful"}


# Route for user login and token generation
@router.post("/login")
async def login(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # User login logic
    username = credentials.username
    password = credentials.password

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.verify_password(password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(username)
    refresh_token = user.add_refresh_token()

    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token}


# Route for token refresh
@router.post("/refresh")
async def refresh_token(refresh_token: str):
    # Token refresh logic
    users = db.query(User).all()
    for user in users:
        if refresh_token in user.refresh_tokens.split(","):
            try:
                payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if username is None:
                    raise HTTPException(status_code=401, detail="Invalid token")
            except JWTError:
                raise HTTPException(status_code=401, detail="Invalid token")

            new_access_token = create_access_token(username)
            user.remove_refresh_token(refresh_token)
            new_refresh_token = user.add_refresh_token()

            db.commit()

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
            }

    raise HTTPException(status_code=401, detail="Invalid refresh token")