from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import asyncssh
from jinja2 import Template

from app.core.security import CryptoBox, generate_password
from app.db.models import Server
from app.services.ssh import ensure_dir, put_text, run

log = logging.getLogger(__name__)

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "assets" / "remote-docker-compose.yml.j2"


@dataclass
class PrecheckReport:
    ok: bool
    details: dict[str, str]


async def _check_root(server: Server, crypto: CryptoBox) -> None:
    out, _, _ = await run(server, crypto, "id -u", check=True)
    if out.strip() != "0":
        raise RuntimeError("SSH user is not root (id -u != 0). Please connect as root.")


async def _check_docker(server: Server, crypto: CryptoBox) -> None:
    await run(server, crypto, "command -v docker >/dev/null", check=True)
    await run(server, crypto, "docker --version", check=True)
    await run(server, crypto, "docker compose version", check=True)


async def _check_tun(server: Server, crypto: CryptoBox) -> None:
    await run(server, crypto, "test -c /dev/net/tun", check=True)


async def _check_port_free_tcp(server: Server, crypto: CryptoBox, port: int) -> None:
    # If any listener exists on :port -> return exit code 2 (busy)
    script = f"ss -H -lnt | awk '{{print $4}}' | grep -qE '(:{port}$|\\]:{port}$)' && exit 2 || exit 0"
    cmd = "bash -lc " + asyncssh.quote(script)
    _, _, code = await run(server, crypto, cmd, check=False)
    if code == 2:
        raise RuntimeError(f"TCP port {port} is already in use on the server.")


async def _check_port_free_udp(server: Server, crypto: CryptoBox, port: int) -> None:
    script = f"ss -H -lnu | awk '{{print $4}}' | grep -qE '(:{port}$|\\]:{port}$)' && exit 2 || exit 0"
    cmd = "bash -lc " + asyncssh.quote(script)
    _, _, code = await run(server, crypto, cmd, check=False)
    if code == 2:
        raise RuntimeError(f"UDP port {port} is already in use on the server.")


async def precheck(server: Server, crypto: CryptoBox) -> PrecheckReport:
    details: dict[str, str] = {}
    try:
        await _check_root(server, crypto)
        details["root"] = "ok"
        await _check_docker(server, crypto)
        details["docker"] = "ok"
        await _check_tun(server, crypto)
        details["/dev/net/tun"] = "ok"
        await _check_port_free_tcp(server, crypto, server.web_ui_port)
        details[f"tcp:{server.web_ui_port}"] = "free"
        await _check_port_free_udp(server, crypto, server.wg_port)
        details[f"udp:{server.wg_port}"] = "free"
        await ensure_dir(server, crypto, server.deploy_dir)
        details["deploy_dir"] = server.deploy_dir
        return PrecheckReport(ok=True, details=details)
    except Exception as e:  # noqa: BLE001
        details["error"] = str(e)
        return PrecheckReport(ok=False, details=details)


def render_remote_compose() -> str:
    raw = TEMPLATE_PATH.read_text(encoding="utf-8")
    t = Template(raw)
    return t.render()


def build_remote_env(server: Server, crypto: CryptoBox) -> tuple[str, str]:
    # returns (env_text, nginx_password_plain)
    nginx_password = crypto.decrypt(server.nginx_password_enc)
    if not nginx_password:
        nginx_password = generate_password(24)

    env = f"""WEB_UI_PORT={server.web_ui_port}
WG_PORT={server.wg_port}
AWG_IMAGE={server.awg_image}
NGINX_USER={server.nginx_user}
NGINX_PASSWORD={nginx_password}
AUTO_START_SERVERS=true
DEFAULT_PORT={server.wg_port}
"""
    return env, nginx_password


async def deploy(server: Server, crypto: CryptoBox) -> None:
    compose = render_remote_compose()
    env_text, nginx_password = build_remote_env(server, crypto)

    # Ensure we store nginx password (encrypted) in DB once (caller persists)
    if not server.nginx_password_enc:
        server.nginx_password_enc = crypto.encrypt(nginx_password)

    await ensure_dir(server, crypto, server.deploy_dir)

    remote_compose_path = f"{server.deploy_dir}/docker-compose.yml"
    remote_env_path = f"{server.deploy_dir}/.env"

    await put_text(server, crypto, remote_compose_path, compose)
    await put_text(server, crypto, remote_env_path, env_text)

    cmd = "bash -lc " + asyncssh.quote(f"cd {server.deploy_dir} && docker compose pull && docker compose up -d")
    out, err, _ = await run(server, crypto, cmd, check=True)
    if out.strip():
        log.info("Deploy stdout: %s", out.strip())
    if err.strip():
        log.warning("Deploy stderr: %s", err.strip())
