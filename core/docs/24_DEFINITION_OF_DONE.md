# 24 — Definition of Done (universal, kedua paket)

Sebuah task selesai bila SEMUA terpenuhi:
- [ ] Kriteria terima terkait hijau (`docs/23_ACCEPTANCE_CRITERIA.md` core atau `../edge/docs/23_ACCEPTANCE_CRITERIA.md`).
- [ ] Tes unit/feature paket yang disentuh hijau (perintah di `11` paket masing-masing).
- [ ] Harness hijau untuk setiap aksi/kapsul yang disentuh, termasuk siklus wajib `apply → verify → apply(skipped) → compensate → jejak nol`.
- [ ] `make catalog-validate contract-test` hijau bila menyentuh `kontrak/`, `catalog/`, `capsules/`, atau kode pesan.
- [ ] Tidak ada pelonggaran tes, verifikasi tanda tangan, kebijakan, atau level risiko.
- [ ] Setiap aksi/perubahan state baru menghasilkan entri audit.
- [ ] Tidak ada rahasia di log/audit/fixture (tes grup `redaction` core; pemindaian pola di edge).
- [ ] Guardrail dipatuhi (`20` & `21` paket terkait); `sadmin:forbidden-scan` hijau.
- [ ] Sesuai struktur & penamaan (`12` paket terkait); lint bersih (`pint`/`phpstan` atau `go vet`/`staticcheck`).
- [ ] Dokumen pemilik fakta diperbarui bila fakta berubah, lalu `bash scripts/validate.sh` hijau.
- [ ] UI (core): hanya token & komponen dari `docs/26_UI_CONVENTIONS.md`; empat state ada; berfungsi di light & dark.
