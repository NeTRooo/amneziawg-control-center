from __future__ import annotations

import logging
from typing import Optional

import asyncssh

from app.core.config import settings
from app.core.security import CryptoBox
from app.db.models import Instance

log = logging.getLogger(__name__)


async def connect(instance: Instance, crypto: CryptoBox) -> asyncssh.SSHClientConnection:
    password = crypto.decrypt(instance.ssh_password_enc)
    key_text = crypto.decrypt(instance.ssh_private_key_enc)
    key_pass = crypto.decrypt(instance.ssh_private_key_passphrase_enc)

    client_keys = None
    if key_text:
        key = asyncssh.import_private_key(key_text, passphrase=key_pass)
        client_keys = [key]

    known_hosts = None if settings.accept_unknown_ssh_host_keys else "~/.ssh/known_hosts"

    return await asyncssh.connect(
        instance.host,
        port=instance.ssh_port,
        username=instance.ssh_user,
        password=password if password else None,
        client_keys=client_keys,
        known_hosts=known_hosts,
        connect_timeout=settings.ssh_connect_timeout,
    )


async def run(instance: Instance, crypto: CryptoBox, command: str, *, check: bool = False) -> tuple[str, str, int]:
    async with await connect(instance, crypto) as conn:
        res = await conn.run(command, check=check, timeout=settings.ssh_command_timeout)
        return res.stdout, res.stderr, res.exit_status


async def ensure_dir(instance: Instance, crypto: CryptoBox, path: str) -> None:
    await run(instance, crypto, f"mkdir -p {path}", check=True)


async def put_text(instance: Instance, crypto: CryptoBox, remote_path: str, content: str) -> None:
    async with await connect(instance, crypto) as conn:
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "w") as f:
                await f.write(content)
