def scan_nik(nik: str) -> str:
    if not nik.isdigit() or len(nik) != 16:
        return "❌ NIK harus 16 digit angka."
    prov = nik[:2]; kab = nik[2:4]; kec = nik[4:6]
    tgl = nik[6:8]; bln = nik[8:10]; thn = nik[10:12]
    hari = int(tgl) - 40 if int(tgl) > 40 else int(tgl)
    gender = "Perempuan" if int(tgl) > 40 else "Laki-laki"
    return (
        f"🆔 *NIK*: `{nik}`\n"
        f"🏙️ *Provinsi code*: `{prov}`\n"
        f"🏢 *Kab/Kota code*: `{kab}`\n"
        f"🏘️ *Kecamatan code*: `{kec}`\n"
        f"📅 *Tanggal lahir*: `{hari:02d}-{bln}-19{thn}`\n"
        f"👤 *Jenis kelamin*: `{gender}`\n"
        f"🔢 *Uniq code*: `{nik[12:]}`"
    )
