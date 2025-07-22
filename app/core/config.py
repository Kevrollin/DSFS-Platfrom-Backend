from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "decentralized_funding"
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()