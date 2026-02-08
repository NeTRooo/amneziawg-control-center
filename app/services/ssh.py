from __future__ import annotations

import logging

import asyncssh

from app.core.config import settings
from app.core.security import CryptoBox
from app.db.models import Server

log = logging.getLogger(__name__)


async def connect(server: Server, crypto: CryptoBox) -> asyncssh.SSHClientConnection:
    password = crypto.decrypt(server.ssh_password_enc)
    key_text = crypto.decrypt(server.ssh_private_key_enc)
    key_pass = crypto.decrypt(server.ssh_private_key_passphrase_enc)

    client_keys = None
    if key_text:
        key = asyncssh.import_private_key(key_text, passphrase=key_pass)
        client_keys = [key]

    known_hosts = None if settings.accept_unknown_ssh_host_keys else "~/.ssh/known_hosts"

    return await asyncssh.connect(
        server.host,
        port=server.ssh_port,
        username=server.ssh_user,
        password=password,
        client_keys=client_keys,
        known_hosts=known_hosts,
        connect_timeout=settings.ssh_connect_timeout,
    )


async def run(server: Server, crypto: CryptoBox, command: str, check: bool = True) -> tuple[str, str, int]:
    async with await connect(server, crypto) as conn:
        res = await conn.run(command, check=check, timeout=settings.ssh_command_timeout)
        return res.stdout, res.stderr, res.exit_status


async def put_text(server: Server, crypto: CryptoBox, remote_path: str, text: str) -> None:
    """Write text to a remote path using a single SSH command.

    We write to a temp file and `install` it into place with mode 600.
    """
    quoted_path = asyncssh.quote(remote_path)
    script = f"""set -euo pipefail
tmp=$(mktemp)
cat > "$tmp" <<'__EOF__'
{text}
__EOF__
install -m 600 "$tmp" {quoted_path}
rm -f "$tmp"
"""
    cmd = "bash -lc " + asyncssh.quote(script)
    await run(server, crypto, cmd, check=True)


async def ensure_dir(server: Server, crypto: CryptoBox, remote_dir: str) -> None:
    script = f"mkdir -p {asyncssh.quote(remote_dir)} && chmod 700 {asyncssh.quote(remote_dir)}"
    cmd = "bash -lc " + asyncssh.quote(script)
    await run(server, crypto, cmd, check=True)
