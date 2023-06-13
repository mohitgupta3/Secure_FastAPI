import sys
sys.path.append(".")

from sqlalchemy.orm import sessionmaker
from .engine import engine

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()