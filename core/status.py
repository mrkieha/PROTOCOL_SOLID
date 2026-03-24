"""
status.py — агрегирует статус AWG-туннеля и MTProto-прокси в один объект.
"""

import psutil
import platform
import subprocess
from datetime import datetime
from core import awg_manager, proxy_manager


def get_full_status(port: int = 443) -> dict:
    """Собираем полный статус системы для API /api/status."""
    awg    = awg_manager.get_status()
    proxy  = proxy_manager.get_status(port=port)
    system = _system_info()

    return {
        "timestamp": datetime.now().isoformat(),
        "awg":       awg,
        "proxy":     proxy,
        "system":    system,
    }


def _system_info() -> dict:
    info = {
        "os":      platform.platform(),
        "distro":  _get_distro(),
        "cpu":     psutil.cpu_percent(interval=0.1),
        "ram":     _ram_info(),
        "uptime":  _uptime(),
    }
    return info


def _get_distro() -> str:
    try:
        import distro
        return distro.name(pretty=True)
    except ImportError:
        pass
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.system()


def _ram_info() -> dict:
    mem = psutil.virtual_memory()
    return {
        "total":   _human(mem.total),
        "used":    _human(mem.used),
        "percent": mem.percent,
    }


def _uptime() -> str:
    try:
        boot = psutil.boot_time()
        from datetime import datetime
        delta = datetime.now().timestamp() - boot
        h = int(delta // 3600)
        m = int((delta % 3600) // 60)
        return f"{h}ч {m}м"
    except Exception:
        return "—"


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n} TB"
