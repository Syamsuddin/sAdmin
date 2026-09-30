#!/usr/bin/env python3
"""token_ledger.py — Buku besar konsumsi token paket VCBD (akumulatif).

Mencatat ke docs/_TOKEN_LEDGER.json dua jenis angka:
  [ESTIMASI]  deterministik dari ukuran file (char / chars-per-token, default 3.5)
              — genesis saat paket lahir (ditulis scaffold.py), lalu per task via `log`.
  [TERUKUR]   dari transkrip lokal Claude Code (~/.claude/projects/*.jsonl, field
              `usage` per pesan) via `sync-cc` — BEST EFFORT: format internal
              Claude Code bisa berubah; kegagalan parsing dilaporkan, bukan ditebak.

KETERBATASAN JUJUR: sesi chat di claude.ai tidak bisa diukur dari dalam skill
(model tak punya akses meteran); untuk itu hanya tersedia estimasi.

Perintah:
  estimate [--route "Fitur baru"] [--all-routes]   hitung est token muatan rute
  log --route "..." [--task "..."]                 catat 1 task (est) + akumulasi
  sync-cc [--cc-dir DIR]                           tarik angka terukur Claude Code
  report                                           akumulasi genesis -> terakhir
Opsi umum: --root DIR (default .), --cpt N (chars per token, default 3.5)
"""
import argparse, json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER_NAME = "_TOKEN_LEDGER.json"


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def est_tokens(chars: int, cpt: float) -> int:
    return round(chars / cpt)


# ---------- rute: dibaca dari INDEX.md (rumah tunggal, keluaran scaffold) ----------
def parse_routes(root: Path):
    """Kembalikan {nama_rute: [nn,...]} dari tabel '## Rute' INDEX.md."""
    idx = root / "INDEX.md"
    routes = {}
    if not idx.is_file():
        return routes
    in_table = False
    for line in idx.read_text(encoding="utf-8").splitlines():
        if line.startswith("## Rute"):
            in_table = True
            continue
        if in_table:
            if line.startswith("## "):
                break
            m = re.match(r"\|\s*([^|]+?)\s*\|\s*([0-9,\s]+)\s*\|", line)
            if m and not m.group(1).startswith("-") and "Jenis task" not in m.group(1):
                nums = [n.strip().zfill(2) for n in m.group(2).split(",") if n.strip()]
                if nums:
                    routes[m.group(1)] = nums
    return routes


def doc_file(root: Path, nn: str):
    hits = sorted((root / "docs").glob(f"{nn}_*.md"))
    return hits[0] if hits else None


def route_files(root: Path, nums):
    files = [root / "CLAUDE.md", root / "INDEX.md"]
    files += [p for nn in nums if (p := doc_file(root, nn))]
    return [f for f in files if f.is_file()]


def sum_chars(files):
    return sum(len(f.read_text(encoding="utf-8", errors="replace")) for f in files)


# ---------- buku besar ----------
def ledger_path(root: Path) -> Path:
    return root / "docs" / LEDGER_NAME


def load_ledger(root: Path):
    p = ledger_path(root)
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[PERINGATAN] ledger rusak ({e}); mulai baru, file lama di-backup .bak")
            p.rename(p.with_suffix(".json.bak"))
    return {"meta": {"created": now_iso(), "unit": "token", "cpt_default": 3.5},
            "est_entries": [], "measured_sessions": {}}


def save_ledger(root: Path, led):
    p = ledger_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(led, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cum_est(led):
    return sum(e.get("est_tokens", 0) for e in led["est_entries"])


def cum_measured(led):
    t = {"input": 0, "output": 0, "cache_create": 0, "cache_read": 0}
    for s in led["measured_sessions"].values():
        for k in t:
            t[k] += s.get(k, 0)
    return t


# ---------- perintah ----------
def cmd_estimate(root, args, cpt):
    routes = parse_routes(root)
    if not routes:
        print("[GAGAL] Tabel rute tak terbaca dari INDEX.md — jalankan scaffold.py dulu.")
        return 2
    targets = routes if args.all_routes else {args.route: routes.get(args.route)}
    if not args.all_routes and targets[args.route] is None:
        print(f"[GAGAL] Rute '{args.route}' tak ada. Tersedia: {', '.join(routes)}")
        return 2
    print(f"[ESTIMASI] cpt={cpt} (char/token). Muatan = CLAUDE.md + INDEX.md + dokumen rute (inti).")
    for name, nums in targets.items():
        files = route_files(root, nums)
        ch = sum_chars(files)
        print(f"  {name:32s} {len(files):2d} file  {ch:7,d} char  ~{est_tokens(ch, cpt):6,d} tok")
    return 0


def cmd_log(root, args, cpt):
    routes = parse_routes(root)
    nums = routes.get(args.route)
    if nums is None:
        print(f"[GAGAL] Rute '{args.route}' tak ada di INDEX.md. Tersedia: {', '.join(routes) or '-'}")
        return 2
    files = route_files(root, nums)
    ch = sum_chars(files)
    tok = est_tokens(ch, cpt)
    led = load_ledger(root)
    led["est_entries"].append({"ts": now_iso(), "type": "task", "task": args.task or "-",
                               "route": args.route, "files": len(files),
                               "chars": ch, "cpt": cpt, "est_tokens": tok})
    save_ledger(root, led)
    print(f"[ESTIMASI] task dicatat: '{args.task or '-'}' rute '{args.route}' ~{tok:,} tok")
    print(f"[ESTIMASI] AKUMULASI sejak genesis: ~{cum_est(led):,} tok ({len(led['est_entries'])} entri)")
    return 0


def _iter_cc_jsonl(cc_dirs):
    for d in cc_dirs:
        d = Path(d).expanduser()
        if d.is_dir():
            yield from d.rglob("*.jsonl")


def cmd_sync_cc(root, args, cpt):
    cc_dirs = [args.cc_dir] if args.cc_dir else [
        os.environ.get("CLAUDE_PROJECTS_DIR", ""), "~/.claude/projects", "~/.config/claude/projects"]
    cc_dirs = [d for d in cc_dirs if d]
    rootr = str(root.resolve())
    sessions, files_seen, lines_bad = {}, 0, 0
    for f in _iter_cc_jsonl(cc_dirs):
        files_seen += 1
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    lines_bad += 1
                    continue
                cwd = o.get("cwd") or ""
                if not cwd or os.path.realpath(os.path.expanduser(cwd)) != rootr:
                    continue
                sid = o.get("sessionId") or f.stem
                u = (o.get("message") or {}).get("usage") or o.get("usage") or {}
                if not u:
                    continue
                s = sessions.setdefault(sid, {"input": 0, "output": 0, "cache_create": 0,
                                              "cache_read": 0, "msgs": 0,
                                              "first_ts": o.get("timestamp"), "last_ts": o.get("timestamp"),
                                              "file": str(f)})
                s["input"] += u.get("input_tokens", 0) or 0
                s["output"] += u.get("output_tokens", 0) or 0
                s["cache_create"] += u.get("cache_creation_input_tokens", 0) or 0
                s["cache_read"] += u.get("cache_read_input_tokens", 0) or 0
                s["msgs"] += 1
                if o.get("timestamp"):
                    s["last_ts"] = o["timestamp"]
        except Exception as e:
            print(f"[PERINGATAN] gagal baca {f}: {e}")
    if not sessions:
        print("[TERUKUR] Tak ada transkrip Claude Code untuk proyek ini "
              f"(dicari di: {', '.join(cc_dirs)}; dicocokkan via field cwd == {rootr}).")
        print("  Wajar bila paket belum pernah dipakai di Claude Code, atau format internal berubah.")
        return 0
    led = load_ledger(root)
    for sid, s in sessions.items():
        s["synced_at"] = now_iso()
        led["measured_sessions"][sid] = s  # idempoten: rerun = timpa per sesi
    save_ledger(root, led)
    t = cum_measured(led)
    print(f"[TERUKUR] {len(sessions)} sesi disinkron ({files_seen} file dipindai, {lines_bad} baris dilewati).")
    print(f"[TERUKUR] AKUMULASI: input {t['input']:,} + output {t['output']:,} "
          f"+ cache_create {t['cache_create']:,} + cache_read {t['cache_read']:,} tok")
    print("  Catatan: best-effort dari format internal Claude Code; angka resmi tetap di penagihan Anthropic.")
    return 0


def cmd_report(root, args, cpt):
    led = load_ledger(root)
    ests, meas = led["est_entries"], led["measured_sessions"]
    print("=== LAPORAN AKUMULASI TOKEN (genesis -> terakhir) ===")
    if ests:
        first, last = ests[0]["ts"], ests[-1]["ts"]
        print(f"[ESTIMASI] {len(ests)} entri  |  {first}  ->  {last}")
        print(f"[ESTIMASI] TOTAL ~{cum_est(led):,} tok")
        per_route = {}
        for e in ests:
            per_route.setdefault(e.get("route", "?"), [0, 0])
            per_route[e["route"]][0] += 1
            per_route[e["route"]][1] += e.get("est_tokens", 0)
        for r, (n, t) in sorted(per_route.items(), key=lambda x: -x[1][1]):
            print(f"    {r:32s} {n:3d}x  ~{t:8,d} tok")
    else:
        print("[ESTIMASI] belum ada entri — catat dengan `log --route ...`.")
    if meas:
        t = cum_measured(led)
        total = sum(t.values())
        print(f"[TERUKUR ] {len(meas)} sesi Claude Code  |  TOTAL {total:,} tok "
              f"(in {t['input']:,} / out {t['output']:,} / cache {t['cache_create']+t['cache_read']:,})")
    else:
        print("[TERUKUR ] belum ada — jalankan `sync-cc` dari dalam lingkungan Claude Code.")
    print("Batas jujur: sesi claude.ai tak terukur dari dalam skill; angka terukur hanya dari transkrip Claude Code.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Buku besar token paket VCBD")
    ap.add_argument("--root", default=".")
    ap.add_argument("--cpt", type=float, default=3.5, help="chars per token (estimasi)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("estimate"); p.add_argument("--route", default="Fitur baru (vertical slice)"); p.add_argument("--all-routes", action="store_true")
    p = sub.add_parser("log"); p.add_argument("--route", required=True); p.add_argument("--task", default="")
    p = sub.add_parser("sync-cc"); p.add_argument("--cc-dir", default="")
    sub.add_parser("report")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    return {"estimate": cmd_estimate, "log": cmd_log, "sync-cc": cmd_sync_cc,
            "report": cmd_report}[a.cmd](root, a, a.cpt)


if __name__ == "__main__":
    sys.exit(main())
