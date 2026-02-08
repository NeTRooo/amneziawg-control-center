from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    # Core
    app_name: str = "Amnezia Control Center"
    log_level: str = "INFO"
    app_port: int = 8000

    # Infrastructure
    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/amnezia_manager"
    redis_url: str = "redis://redis:6379/0"

    # Crypto (Fernet 32-byte urlsafe base64)
    encryption_key: str

    # SSH / deploy
    ssh_connect_timeout: float = 10.0
    ssh_command_timeout: float = 30.0
    remote_deploy_dir: str = "/opt/amneziawg-web-ui"
    accept_unknown_ssh_host_keys: bool = True

    # Defaults for remote AmneziaWG Web UI deployment
    default_web_ui_port: int = 8080  # tcp
    default_wg_port: int = 51820  # udp
    default_nginx_user: str = "admin"
    awg_image: str = "alexishw/amneziawg-web-ui:latest"


settings = Settings()
