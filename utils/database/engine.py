from sqlalchemy import create_engine

# PostgreSQL database configuration
DATABASE_URL = "postgresql://user:password@localhost:5432/mydatabase"

engine = create_engine(DATABASE_URL)