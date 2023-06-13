# User model
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    refresh_tokens = Column(String)

    def verify_password(self, password: str):
        return pwd_context.verify(password, self.password_hash)

    def add_refresh_token(self):
        refresh_token = str(uuid4())
        if self.refresh_tokens:
            self.refresh_tokens += f",{refresh_token}"
        else:
            self.refresh_tokens = refresh_token
        return refresh_token

    def remove_refresh_token(self, token: str):
        tokens = self.refresh_tokens.split(",")
        tokens.remove(token)
        self.refresh_tokens = ",".join(tokens)

# Create the database tables
Base.metadata.create_all(bind=engine)