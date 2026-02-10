"""init (instances + rbac)

Revision ID: 0001_init
Revises:
Create Date: 2026-02-08

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "instances",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("ssh_user", sa.String(length=255), nullable=False, server_default="root"),
        sa.Column("auth_method", sa.String(length=32), nullable=False, server_default="key"),
        sa.Column("web_ui_port", sa.Integer(), nullable=False, server_default="8080"),
        sa.Column("wg_port", sa.Integer(), nullable=False, server_default="51820"),
        sa.Column("deploy_dir", sa.String(length=512), nullable=False, server_default="/opt/amneziawg-web-ui"),
        sa.Column("awg_image", sa.String(length=255), nullable=False, server_default="alexishw/amneziawg-web-ui:latest"),
        sa.Column("remote_scheme", sa.String(length=16), nullable=False, server_default="http"),
        sa.Column("nginx_user", sa.String(length=255), nullable=False, server_default="admin"),
        sa.Column("ssh_password_enc", sa.Text(), nullable=True),
        sa.Column("ssh_private_key_enc", sa.Text(), nullable=True),
        sa.Column("ssh_private_key_passphrase_enc", sa.Text(), nullable=True),
        sa.Column("nginx_password_enc", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="new"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_deploy_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_instances_id", "instances", ["id"])
    op.create_index("ix_instances_name", "instances", ["name"])
    op.create_index("ix_instances_host", "instances", ["host"])
    op.create_index("ix_instances_status", "instances", ["status"])

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("global_role", sa.String(length=32), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_global_role", "users", ["global_role"])

    op.create_table(
        "instance_access",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("instance_id", sa.Uuid(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "instance_id", name="uq_instance_access_user_instance"),
    )
    op.create_index("ix_instance_access_id", "instance_access", ["id"])
    op.create_index("ix_instance_access_user_id", "instance_access", ["user_id"])
    op.create_index("ix_instance_access_instance_id", "instance_access", ["instance_id"])
    op.create_index("ix_instance_access_role", "instance_access", ["role"])


def downgrade() -> None:
    op.drop_index("ix_instance_access_role", table_name="instance_access")
    op.drop_index("ix_instance_access_instance_id", table_name="instance_access")
    op.drop_index("ix_instance_access_user_id", table_name="instance_access")
    op.drop_index("ix_instance_access_id", table_name="instance_access")
    op.drop_table("instance_access")

    op.drop_index("ix_users_global_role", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")

    op.drop_index("ix_instances_status", table_name="instances")
    op.drop_index("ix_instances_host", table_name="instances")
    op.drop_index("ix_instances_name", table_name="instances")
    op.drop_index("ix_instances_id", table_name="instances")
    op.drop_table("instances")
