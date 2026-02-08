from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class AuthMethod(str, Enum):
    password = "password"
    key = "key"


class ServerStatus(str, Enum):
    new = "new"
    checking = "checking"
    deploying = "deploying"
    ready = "ready"
    error = "error"
    removed = "removed"


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class ServerBase(SQLModel):
    name: str = Field(index=True)
    host: str = Field(index=True, description="IP or hostname")
    ssh_port: int = Field(default=22)
    ssh_user: str = Field(default="root")
    auth_method: AuthMethod = Field(default=AuthMethod.key)

    # Remote AmneziaWG Web UI ports
    web_ui_port: int = Field(default=8080, description="TCP port for Web UI")
    wg_port: int = Field(default=51820, description="UDP port for WireGuard/AmneziaWG")

    # Deployment config
    deploy_dir: str = Field(default="/opt/amneziawg-web-ui")
    awg_image: str = Field(default="alexishw/amneziawg-web-ui:latest")
    remote_scheme: str = Field(default="http", description="http or https for remote API/UI")

    # Remote basic auth (nginx)
    nginx_user: str = Field(default="admin")


class Server(ServerBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    # Secrets (encrypted at rest)
    ssh_password_enc: Optional[str] = Field(default=None)
    ssh_private_key_enc: Optional[str] = Field(default=None)
    ssh_private_key_passphrase_enc: Optional[str] = Field(default=None)
    nginx_password_enc: Optional[str] = Field(default=None)

    status: ServerStatus = Field(default=ServerStatus.new, index=True)
    last_error: Optional[str] = Field(default=None)
    last_check_at: Optional[dt.datetime] = Field(default=None)
    last_deploy_at: Optional[dt.datetime] = Field(default=None)

    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


class ServerCreate(ServerBase):
    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_private_key_passphrase: Optional[str] = None

    # Optional: set your own nginx password for remote Web UI. If not set, one will be generated.
    nginx_password: Optional[str] = None

    deploy_now: bool = True


class ServerUpdate(SQLModel):
    name: Optional[str] = None
    web_ui_port: Optional[int] = None
    wg_port: Optional[int] = None
    remote_scheme: Optional[str] = None
    # Rotating credentials is supported (optional)
    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_private_key_passphrase: Optional[str] = None


class ServerRead(ServerBase):
    id: uuid.UUID
    status: ServerStatus
    last_error: Optional[str]
    last_check_at: Optional[dt.datetime]
    last_deploy_at: Optional[dt.datetime]
    created_at: dt.datetime
    updated_at: dt.datetime

    remote_url: str

    @staticmethod
    def from_orm_server(s: "Server") -> "ServerRead":
        remote_url = f"{s.remote_scheme}://{s.host}:{s.web_ui_port}"
        return ServerRead(
            id=s.id,
            name=s.name,
            host=s.host,
            ssh_port=s.ssh_port,
            ssh_user=s.ssh_user,
            auth_method=s.auth_method,
            web_ui_port=s.web_ui_port,
            wg_port=s.wg_port,
            deploy_dir=s.deploy_dir,
            awg_image=s.awg_image,
            remote_scheme=s.remote_scheme,
            nginx_user=s.nginx_user,
            status=s.status,
            last_error=s.last_error,
            last_check_at=s.last_check_at,
            last_deploy_at=s.last_deploy_at,
            created_at=s.created_at,
            updated_at=s.updated_at,
            remote_url=remote_url,
        )
