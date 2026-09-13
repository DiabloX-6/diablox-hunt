async def leakscan_cmd(update, context):
    uid = update.effective_user.id
    ok, msg = cek_akses_osint(uid)
    if not ok:
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=owner_button())
        return

    threads = 20
    mode = "medium"

    if context.args:
        # Argumen 1: threads (angka)
        if context.args[0].isdigit():
            threads = int(context.args[0])
            threads = max(1, min(threads, 50))
            # Argumen 2: mode (kalo ada)
            if len(context.args) > 1 and context.args[1] in ("loose", "medium", "strict"):
                mode = context.args[1]
        # Argumen 1: mode langsung (kalo ga angka)
        elif context.args[0] in ("loose", "medium", "strict"):
            mode = context.args[0]

    mode_emoji = {"loose": "🟢", "medium": "🟡", "strict": "🔴"}[mode]
    mode_desc = {
        "loose": "Longgar (banyak hasil, ada false positive)",
        "medium": "Medium (balance)",
        "strict": "Galak (cuma yang akurat)",
    }[mode]

    m = await update.message.reply_text(
        f"🔍 *Leak Aggregator* dimulai...\n"
        f"{mode_emoji} Mode: `{mode.upper()}`\n"
        f"📝 _{mode_desc}_\n"
        f"🧵 Thread: `{threads}`\n"
        f"⏱️ Estimasi: 3-10 menit\n\n"
        f"_Bot akan kirim hasil kalo udah selesai._",
        parse_mode="Markdown"
    )

    try:
        result = await asyncio.to_thread(run_leak_scan, threads, mode)
    except Exception as e:
        await m.edit_text(f"❌ Error: `{e}`", parse_mode="Markdown")
        return

    if not result or not result.get("results"):
        await m.edit_text(
            f"✅ Selesai (mode `{mode.upper()}`), tapi gak ada data leak ditemukan.\n\n"
            f"Coba pake mode lain:\n"
            f"`/leakscan {threads} loose` — lebih longgar",
            parse_mode="Markdown"
        )
        return

    data = result["results"]
    total_patterns = {}
    for r in data:
        for k, v in r["findings"].items():
            total_patterns[k] = total_patterns.get(k, 0) + len(v)

    text = (
        f"✅ *LEAK SCAN SELESAI*\n\n"
        f"{mode_emoji} Mode: `{mode.upper()}`\n"
        f"📊 Sumber ditemukan: `{len(data)}`\n"
        f"🧵 Thread: `{threads}`\n"
        f"⏰ Waktu: `{result['time']}`\n\n"
        f"*Pattern ditemukan:*\n"
    )
    for k, v in sorted(total_patterns.items(), key=lambda x: -x[1]):
        text += f"  • `{k}`: {v}\n"

    text += (
        f"\n💡 _Coba mode lain:_\n"
        f"`/leakscan {threads} loose` — longgar\n"
        f"`/leakscan {threads} strict` — galak"
    )

    await m.edit_text(text[:4000], parse_mode="Markdown")

    try:
        with open(result["file"], "rb") as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(result["file"]),
                caption=f"📄 Mode {mode.upper()} - {len(data)} sumber"
            )
    except Exception as e:
        logger.error(f"Kirim file leak: {e}")
