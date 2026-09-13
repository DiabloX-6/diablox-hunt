import subprocess
import shutil

def scan_email(email: str) -> str:
    if not shutil.which("holehe"):
        return "❌ `holehe` tidak terinstall. Jalankan: `pip install holehe`"
    try:
        out = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True, text=True, timeout=180
        ).stdout
        if not out.strip():
            return f"🔍 *{email}*\n\n_Tidak terdaftar di situs manapun._"
        return f"🔍 *Email: {email}*\n\n```\n{out[:3500]}\n```"
    except subprocess.TimeoutExpired:
        return "⏰ Timeout (180s). Coba lagi."
    except Exception as e:
        return f"❌ Error: {e}"
