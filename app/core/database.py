from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "decentralized_funding")


class Database:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    async def connect_to_mongo(cls):
        cls.client = AsyncIOMotorClient(MONGODB_URL)
        try:
            await cls.client.admin.command('ping')
            cls.db = cls.client[DATABASE_NAME]
            print("Successfully connected to MongoDB")
        except Exception as e:
            print(f"Could not connect to MongoDB: {e}")
            raise e

    @classmethod
    async def close_mongo_connection(cls):
        if cls.client:
            cls.client.close()
            print("MongoDB connection closed")

    @classmethod
    def get_db(cls):
        return cls.db


db = Database()