from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum
from typing import Optional

import sqlalchemy as sa
from sqlalchemy import Column
from sqlmodel import Field, SQLModel


def utcnow() -> dt.datetime:
    """
    Return a UTC timestamp as a *naive* datetime.

    Our Postgres columns are defined as TIMESTAMP WITHOUT TIME ZONE, and asyncpg
    expects offset-naive datetimes for such columns. Using timezone-aware
    datetimes here leads to "can't subtract offset-naive and offset-aware
    datetimes" errors when binding parameters.
    """
    # Use utcnow() which returns a naive datetime representing UTC time.
    return dt.datetime.utcnow()


class AuthMethod(str, Enum):
    password = "password"
    key = "key"


class InstanceStatus(str, Enum):
    new = "new"
    checking = "checking"
    deploying = "deploying"
    ready = "ready"
    error = "error"
    removed = "removed"


class GlobalRole(str, Enum):
    admin = "admin"
    operator = "operator"
    viewer = "viewer"


class InstanceRole(str, Enum):
    admin = "admin"
    operator = "operator"
    viewer = "viewer"


ROLE_RANK: dict[str, int] = {
    GlobalRole.viewer: 1,
    GlobalRole.operator: 2,
    GlobalRole.admin: 3,
    InstanceRole.viewer: 1,
    InstanceRole.operator: 2,
    InstanceRole.admin: 3,
}


# -----------------------------
# Instances (remote hosts)
# -----------------------------
class InstanceBase(SQLModel):
    name: str = Field(index=True)
    host: str = Field(index=True, description="IP or hostname")
    ssh_port: int = Field(default=22)
    ssh_user: str = Field(default="root")
    # NOTE: native_enum=False => store as VARCHAR in Postgres (no CREATE TYPE)
    auth_method: AuthMethod = Field(
        default=AuthMethod.key,
        sa_column=Column(
            sa.Enum(AuthMethod, native_enum=False, length=32),
            nullable=False,
            server_default=AuthMethod.key.value,
        ),
    )

    # Remote Web UI ports
    web_ui_port: int = Field(default=8080, description="TCP port for Web UI (NGINX_PORT)")
    wg_port: int = Field(default=51820, description="UDP port for AmneziaWG")

    # Remote deployment
    deploy_dir: str = Field(default="/opt/amneziawg-web-ui")
    awg_image: str = Field(default="alexishw/amneziawg-web-ui:latest")
    remote_scheme: str = Field(default="http", description="http or https")

    # Remote basic auth (nginx)
    nginx_user: str = Field(default="admin")


class Instance(InstanceBase, table=True):
    __tablename__ = "instances"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    # Secrets (encrypted at rest)
    ssh_password_enc: Optional[str] = Field(default=None)
    ssh_private_key_enc: Optional[str] = Field(default=None)
    ssh_private_key_passphrase_enc: Optional[str] = Field(default=None)
    nginx_password_enc: Optional[str] = Field(default=None)

    status: InstanceStatus = Field(
        default=InstanceStatus.new,
        sa_column=Column(
            sa.Enum(InstanceStatus, native_enum=False, length=32),
            nullable=False,
            server_default=InstanceStatus.new.value,
        ),
    )
    last_error: Optional[str] = Field(default=None)
    last_check_at: Optional[dt.datetime] = Field(default=None)
    last_deploy_at: Optional[dt.datetime] = Field(default=None)

    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


class InstanceCreate(InstanceBase):
    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_private_key_passphrase: Optional[str] = None

    # Optional: set your own nginx password for remote Web UI. If not set, one will be generated.
    nginx_password: Optional[str] = None

    deploy_now: bool = True


class InstanceUpdate(SQLModel):
    name: Optional[str] = None
    web_ui_port: Optional[int] = None
    wg_port: Optional[int] = None
    remote_scheme: Optional[str] = None

    ssh_password: Optional[str] = None
    ssh_private_key: Optional[str] = None
    ssh_private_key_passphrase: Optional[str] = None
    nginx_password: Optional[str] = None


class InstanceRead(InstanceBase):
    id: uuid.UUID
    status: InstanceStatus
    last_error: Optional[str]
    last_check_at: Optional[dt.datetime]
    last_deploy_at: Optional[dt.datetime]
    created_at: dt.datetime
    updated_at: dt.datetime


# -----------------------------
# Users / RBAC
# -----------------------------
class UserBase(SQLModel):
    username: str = Field(index=True)
    is_active: bool = Field(default=True)
    global_role: GlobalRole = Field(
        default=GlobalRole.viewer,
        sa_column=Column(
            sa.Enum(GlobalRole, native_enum=False, length=32),
            nullable=False,
            server_default=GlobalRole.viewer.value,
        ),
    )


class User(UserBase, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    password_hash: str = Field(nullable=False)

    created_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)


class UserCreate(SQLModel):
    username: str
    password: str
    global_role: GlobalRole = GlobalRole.viewer
    is_active: bool = True


class UserRead(UserBase):
    id: uuid.UUID
    created_at: dt.datetime
    updated_at: dt.datetime


class InstanceAccess(SQLModel, table=True):
    __tablename__ = "instance_access"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    user_id: uuid.UUID = Field(foreign_key="users.id", index=True)
    instance_id: uuid.UUID = Field(foreign_key="instances.id", index=True)
    role: InstanceRole = Field(
        default=InstanceRole.viewer,
        sa_column=Column(
            sa.Enum(InstanceRole, native_enum=False, length=32),
            nullable=False,
            server_default=InstanceRole.viewer.value,
        ),
    )

    created_at: dt.datetime = Field(default_factory=utcnow)


class InstanceAccessCreate(SQLModel):
    user_id: uuid.UUID
    role: InstanceRole


class InstanceAccessRead(SQLModel):
    id: uuid.UUID
    user_id: uuid.UUID
    instance_id: uuid.UUID
    role: InstanceRole
    created_at: dt.datetime
