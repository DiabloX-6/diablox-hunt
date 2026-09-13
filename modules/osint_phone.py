import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def scan_phone(number: str) -> str:
    try:
        p = phonenumbers.parse(number, None)
        valid = phonenumbers.is_valid_number(p)
        return (
            f"📱 *Nomor*: `{number}`\n"
            f"✅ *Valid*: `{valid}`\n"
            f"🌍 *Negara*: `{geocoder.description_for_number(p, 'id') or '-'}`\n"
            f"📡 *Carrier*: `{carrier.name_for_number(p, 'id') or '-'}`\n"
            f"🕐 *Timezone*: `{', '.join(timezone.time_zones_for_number(p)) or '-'}`\n"
            f"🔢 *E164*: `{phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)}`"
        )
    except Exception as e:
        return f"❌ Error: {e}"
