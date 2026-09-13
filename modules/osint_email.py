import subprocess
import shutil
import sys
from pathlib import Path


def _find_holehe() -> str:
    """Cari binary holehe — cek di venv dulu, baru PATH sistem."""
    # Cek di venv sebelah python yang lagi jalan
    venv_bin = Path(sys.executable).parent / "holehe"
    if venv_bin.exists():
        return str(venv_bin)

    # Fallback: cek PATH sistem
    which = shutil.which("holehe")
    if which:
        return which

    return ""


def scan_email(email: str) -> str:
    holehe_bin = _find_holehe()
    if not holehe_bin:
        return (
            "❌ `holehe` tidak terinstall.\n\n"
            "Install: `/root/diablox-hunt/venv/bin/pip install holehe`"
        )
    try:
        out = subprocess.run(
            [holehe_bin, email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=180
        ).stdout
        if not out.strip():
            return f"🔍 *{email}*\n\n_Tidak terdaftar di situs manapun._"
        return f"🔍 *Email: {email}*\n\n```\n{out[:3500]}\n```"
    except subprocess.TimeoutExpired:
        return "⏰ Timeout (180s). Coba lagi."
    except Exception as e:
        return f"❌ Error: {e}"
