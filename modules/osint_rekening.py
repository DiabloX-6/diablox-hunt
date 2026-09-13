import requests

def scan_rekening(norek: str) -> str:
    norek = norek.replace(" ", "").replace("-", "")
    if not norek.isdigit() or len(norek) < 8:
        return "❌ Format rekening tidak valid."
    try:
        r = requests.get(
            f"https://cekrekening.github.io/api/{norek}",
            timeout=10
        )
        if r.status_code == 200:
            return f"🏦 *Rekening: {norek}*\n\n`{r.text[:800]}`"
        return f"⚠️ Status {r.status_code} — data tidak tersedia."
    except Exception as e:
        return f"❌ Error: {e}"
