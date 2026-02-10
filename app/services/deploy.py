from __future__ import annotations
import logging
from dataclasses import dataclass
from pathlib import Path
from jinja2 import Template
from app.core.config import settings
from app.core.security import CryptoBox
from app.db.models import Instance
from app.services.ssh import ensure_dir, put_text, run
log = logging.getLogger(__name__)
TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "assets" / "remote-docker-compose.yml.j2"
@dataclass
class PrecheckReport:
    ok: bool
    details: dict[str, str]
async def _check_root(instance: Instance, crypto: CryptoBox) -> None:
    out, _, _ = await run(instance, crypto, "id -u", check=True)
    if out.strip() != "0":
        raise RuntimeError("SSH user is not root (id -u != 0). Please connect as root.")
async def _check_docker(instance: Instance, crypto: CryptoBox) -> None:
    await run(instance, crypto, "command -v docker >/dev/null", check=True)
async def _check_compose(instance: Instance, crypto: CryptoBox) -> None:
    # Docker Compose v2: `docker compose`
    out, _, code = await run(instance, crypto, "docker compose version >/dev/null 2>&1; echo $?", check=False)
    if out.strip() == "0":
        return
    # legacy docker-compose
    await run(instance, crypto, "command -v docker-compose >/dev/null", check=True)
async def _check_ports_free(instance: Instance, crypto: CryptoBox) -> None:
    tcp = instance.web_ui_port
    udp = instance.wg_port
    # TCP listeners + processes (requires root)
    out, _, _ = await run(instance, crypto, "ss -lntpH 2>/dev/null || netstat -lntp 2>/dev/null || true", check=False)
    if str(tcp) in out:
        raise RuntimeError(f"TCP port {tcp} seems to be in use on remote host. Details:\\n{out[:800]}")
    # UDP listeners + processes
    out, _, _ = await run(instance, crypto, "ss -lnupH 2>/dev/null || netstat -lnup 2>/dev/null || true", check=False)
    if str(udp) in out:
        raise RuntimeError(f"UDP port {udp} seems to be in use on remote host. Details:\\n{out[:800]}")
async def _check_iptables(instance: Instance, crypto: CryptoBox) -> None:
    # Not strict, but warn if missing
    out, _, _ = await run(instance, crypto, "command -v iptables >/dev/null 2>&1; echo $?", check=False)
    if out.strip() != "0":
        raise RuntimeError("iptables is not installed (required for automatic firewall rules).")
async def precheck(instance: Instance, crypto: CryptoBox) -> PrecheckReport:
    details: dict[str, str] = {}
    try:
        await _check_root(instance, crypto)
        details["root"] = "ok"
        await _check_docker(instance, crypto)
        details["docker"] = "ok"
        await _check_compose(instance, crypto)
        details["compose"] = "ok"
        await _check_ports_free(instance, crypto)
        details["ports"] = "ok"
        await _check_iptables(instance, crypto)
        details["iptables"] = "ok"
        return PrecheckReport(ok=True, details=details)
    except Exception as e:  # noqa: BLE001
        details["error"] = str(e)
        return PrecheckReport(ok=False, details=details)
def _render_compose() -> str:
    tpl = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))
    return tpl.render()
def _render_env(instance: Instance, crypto: CryptoBox) -> str:
    nginx_password = crypto.decrypt(instance.nginx_password_enc) or ""
    return (
        f"AWG_IMAGE={instance.awg_image}\n"
        f"WEB_UI_PORT={instance.web_ui_port}\n"
        f"WG_PORT={instance.wg_port}\n"
        f"NGINX_USER={instance.nginx_user}\n"
        f"NGINX_PASSWORD={nginx_password}\n"
        "AUTO_START_SERVERS=true\n"
        f"DEFAULT_PORT={instance.wg_port}\n"
    )
async def deploy(instance: Instance, crypto: CryptoBox) -> None:
    await ensure_dir(instance, crypto, instance.deploy_dir)
    compose_text = _render_compose()
    env_text = _render_env(instance, crypto)
    await put_text(instance, crypto, f"{instance.deploy_dir}/docker-compose.yml", compose_text)
    await put_text(instance, crypto, f"{instance.deploy_dir}/.env", env_text)
    # Run compose
    cmd = (
        f"cd {instance.deploy_dir} && "
        "(docker compose up -d || docker-compose up -d)"
    )
    out, err, code = await run(instance, crypto, cmd, check=False)
    if code != 0:
        raise RuntimeError(f"docker compose failed: {err or out}")
