# INDEX — Peta Konteks
Untuk AI: baca ini sebelum task. Muat hanya dokumen yang ditunjuk. JANGAN muat semua.

## Tier 0 — selalu aktif
CLAUDE.md (inti). Jangan baca ulang sumbernya kecuali butuh detail.
Esensi 17_AGENT_WORKFLOW (alur per-task) & 19_TASK_TEMPLATE (format task) sudah diringkas di CLAUDE.md — keduanya sengaja TIDAK ada di rute task. Muat dokumen penuhnya hanya saat butuh detail alur/format, bukan tiap task.

## Rute: jenis task → dokumen
| Jenis task | Muat (inti) | Kondisional / catatan |
|---|---|---|
| Fitur baru (vertical slice) | 01,02,06,07,11,23 | cek 02 dulu; +04 istilah domain ambigu; +05 sentuh peran/izin; +13 jenis tes baru; format task: 19 (esensi di CLAUDE); +26 bila menyentuh tampilan |
| Halaman/komponen UI baru | 02,11,23,26 | +06 bila alur baru; +05 bila sentuh peran/izin; empat state wajib (26) |
| Ubah skema DB / migrasi | 07,11,13,22 | ⚠️ irreversibel; 22 wajib; +04 bila entitas/istilah baru |
| Perbaikan bug | 11,13,14,16,18 | jangan lewat scope bug; 11 utk repro+tes regresi |
| Endpoint/API baru | 06,07,08,11,13,21 | 21 bila sensitif |
| Perubahan keamanan | 15,20,21,22 | ⚠️ gerbang manusia |
| Tambah peran/izin | 05,06,21 | — |
| Refactor arsitektur | 04,08,22 | jangan ubah keputusan sengaja |
| Observability/logging | 14,15,16 | — |
| Setup lingkungan | 09,10,11,12 | — |
| Rilis | 11,15,22,25 | ⚠️ ikuti 25 berurutan; +24 bila butuh DoD rinci |
| Strategi/scope | 00,01,02,03 | tanpa kode |

## Indeks per klaster (path: docs/NN_NAMA.md)
- 00–03 Strategis: EXECUTIVE_SUMMARY · PRD · SCOPE · ROADMAP
- 04–07 Domain: DOMAIN_MODEL · USER_ROLE · BUSINESS_PROCESS · DATA_MODEL
- 08–12 Fondasi Teknis: ARCHITECTURE · STACK · DEV_ENV · COMMANDS · PROJECT_STRUCTURE
- 13–16 Kualitas & Operasi: TESTING · ERROR_HANDLING · OBSERVABILITY · DEBUGGING_GUIDE
- 17–22 Perilaku-Agen: AGENT_WORKFLOW · REPAIR_RULES · TASK_TEMPLATE · GUARDRAILS · SECURITY_RULES · CHANGE_POLICY
- 23–25 Gerbang Selesai: ACCEPTANCE_CRITERIA · DEFINITION_OF_DONE · RELEASE_CHECKLIST
- 26 Antarmuka (kondisional): UI_CONVENTIONS — token BEKU, inventaris, empat state, larangan

## Aturan emas
1. Ragu? Muat paling sedikit dulu (kolom Muat), tambah Kondisional/eskalasi hanya bila kurang.
2. Task irreversibel → wajib baca 22 + minta konfirmasi.
3. Konflik antar dokumen → berhenti, laporkan, minta keputusan.
4. Patokan selesai = 23 + 24, bukan kesempurnaan.
5. Brownfield: dokumen ≠ kode aktual → KODE menang, hentikan & lapor selisih (lihat presedensi sumber kebenaran).
6. 23 hanya memuat fitur AKTIF. Fitur yang sudah diterima (kriteria terpenuhi, tes hijau) diarsipkan ke docs/_archive/23-{fitur}.md — penegakannya pindah ke test suite.
7. UI: hanya nilai dari tabel token 26 dan komponen dari inventaris 26; kata sifat estetika bukan spesifikasi — bila token tak menjawab, berhenti & tanya, jangan mengarang.
