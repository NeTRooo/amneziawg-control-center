"""init

Revision ID: 0001_init
Revises: 
Create Date: 2026-02-08

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "server",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("ssh_user", sa.String(), nullable=False, server_default="root"),
        sa.Column("auth_method", sa.String(), nullable=False, server_default="key"),
        sa.Column("web_ui_port", sa.Integer(), nullable=False, server_default="8080"),
        sa.Column("wg_port", sa.Integer(), nullable=False, server_default="51820"),
        sa.Column("deploy_dir", sa.String(), nullable=False, server_default="/opt/amneziawg-web-ui"),
        sa.Column("awg_image", sa.String(), nullable=False, server_default="alexishw/amneziawg-web-ui:latest"),
        sa.Column("remote_scheme", sa.String(), nullable=False, server_default="http"),
        sa.Column("nginx_user", sa.String(), nullable=False, server_default="admin"),
        sa.Column("ssh_password_enc", sa.Text(), nullable=True),
        sa.Column("ssh_private_key_enc", sa.Text(), nullable=True),
        sa.Column("ssh_private_key_passphrase_enc", sa.Text(), nullable=True),
        sa.Column("nginx_password_enc", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="new"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_deploy_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_server_id", "server", ["id"])
    op.create_index("ix_server_name", "server", ["name"])
    op.create_index("ix_server_host", "server", ["host"])
    op.create_index("ix_server_status", "server", ["status"])


def downgrade() -> None:
    op.drop_index("ix_server_status", table_name="server")
    op.drop_index("ix_server_host", table_name="server")
    op.drop_index("ix_server_name", table_name="server")
    op.drop_index("ix_server_id", table_name="server")
    op.drop_table("server")
