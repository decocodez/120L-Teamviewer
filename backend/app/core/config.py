from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    sentinelflow_login_username: str = "admin"
    sentinelflow_login_password: str = "admin"

    sentinelflow_backend_url: str = "http://127.0.0.1:8000"

    teamviewer_base_url: str = "https://webapi.teamviewer.com/api/v1"
    teamviewer_api_token: str = ""

    gemini_api_key: str = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"
    gemini_model: str = "gemini-2.0-flash"


settings = Settings()

