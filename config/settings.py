from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    OPENROUTER_API_KEY: str
    MONGO_URI: str
    MONGO_DB_NAME: str
    MONGO_COLLECTION_NAME: str

    class Config:
        env_file: str = ".env"
        env_file_encoding: str = "utf-8"


settings = Settings()
