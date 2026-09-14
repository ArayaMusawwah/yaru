# Yaru Project
## AUR Supply-Chain Security Layer for Arch Linux

> **Status:** Architecture / Design Specification  
> **Target:** Arch Linux and Arch-based distributions  
> **Primary integration:** `paru`, `makepkg`, `pacman`  
> **Project type:** Local security tool, AUR IDS/IPS, package supply-chain monitor

---

# 1. Latar Belakang

Arch Linux memiliki ekosistem package yang kuat melalui repository resmi dan Arch User Repository (AUR).

Repository resmi seperti:

- `core`
- `extra`
- `multilib`

menyediakan paket binary yang telah dibangun dan ditandatangani melalui mekanisme package signing Arch Linux.

AUR memiliki model yang berbeda. AUR pada dasarnya menyediakan recipe/build instructions seperti:

- `PKGBUILD`
- `.install`
- patch
- source URL
- dependency definition
- build functions

Ketika user menggunakan helper seperti `paru`, recipe tersebut dapat dijalankan oleh sistem untuk menghasilkan paket.

Model ini sangat fleksibel, tetapi juga menciptakan supply-chain attack surface.

Masalah yang ingin diselesaikan Yaru bukan sekadar "apakah executable setelah terinstall mengandung malware", melainkan:

> **Apakah source, maintainer, PKGBUILD, dependency, dan perilaku build package ini layak dipercaya sebelum package masuk ke sistem?**

Yaru dirancang sebagai lapisan keamanan antara package manager/AUR helper dengan sistem.

---

# 2. Tujuan Project

Yaru bertujuan menjadi:

> **AUR Supply-Chain IDS/IPS untuk Arch Linux.**

Yaru menggabungkan:

1. Trust Score
2. Maintainer Change Detection
3. PKGBUILD Scanner
4. Dependency Scanner
5. Threat Intelligence
6. Network Isolation saat build
7. Sandbox Builder
8. Behavior Monitoring
9. Risk Scoring
10. Policy Enforcement

Yaru bukan pengganti `pacman` atau `paru`.

Yaru bertindak sebagai:

```text
Security Decision Layer
        +
Supply-Chain Monitor
        +
Build Sandbox
        +
IDS/IPS
```

---

# 3. Prinsip Utama

## 3.1 Jangan Menganggap AUR = Malware

AUR tidak boleh dianggap sebagai sumber malware secara otomatis.

Model keamanan Yaru:

```text
AUR package
    ↓
Untrusted by default
    ↓
Inspect
    ↓
Evaluate
    ↓
Contain
    ↓
Allow / Warn / Block
```

Tujuannya adalah verifikasi berbasis evidence, bukan ketakutan terhadap AUR.

---

## 3.2 Jangan Menganggap Package Lama Selalu Aman

Package yang telah lama dipercaya harus tetap dianalisis terhadap perubahan terbaru.

Contoh:

```text
Package age       = 6 years
Historical trust  = High
Current maintainer = Changed
PKGBUILD           = Changed
Behavior           = Suspicious
```

Hasil akhir harus tetap dapat:

```text
WARN / BLOCK
```

Prinsip:

> **Historical trust tidak boleh mengalahkan current evidence.**

---

## 3.3 Fast Path untuk Repository Terpercaya

Tidak semua package harus melewati pipeline AUR yang berat.

Yaru membedakan source package berdasarkan trust zone.

```text
Official Repository
        ↓
Fast Path

Trusted Third-Party Repository
        ↓
Trusted Path

AUR
        ↓
Full Security Path

Unknown Repository
        ↓
Restricted Path
```

Tujuannya menjaga keamanan sekaligus mempertahankan performa package management.

---

# 4. Trust Zones

## Zone 0: Official

Contoh:

```text
core
extra
multilib
```

Default treatment:

```text
✓ Repository verification
✓ Package signature verification
✓ Package integrity
✓ Threat intelligence check

Tidak perlu:
- AUR PKGBUILD analysis
- AUR maintainer reputation
- AUR sandbox build
```

Karena user menerima package binary yang telah dibangun repository tersebut.

---

## Zone 1: Trusted Repository

Contoh:

```text
CachyOS repositories
```

Default treatment:

```text
✓ Signature verification
✓ Package integrity
✓ Repository reputation
✓ Threat intelligence
```

Status trust harus configurable dan dapat diturunkan apabila terjadi incident.

---

## Zone 2: Third-Party Repository

Default treatment:

```text
✓ Signature verification
✓ Integrity
✓ Repository reputation
✓ Package provenance
✓ Threat intelligence
```

Yaru dapat meminta enhanced verification berdasarkan risk.

---

## Zone 3: AUR

AUR mendapatkan full pipeline:

```text
Metadata
↓
Static Analysis
↓
Maintainer Analysis
↓
Dependency Analysis
↓
Threat Intelligence
↓
Risk Scoring
↓
Sandbox Build
↓
Behavior Monitoring
↓
Final Policy
```

---

## Zone 4: Unknown / Untrusted

Contoh:

```text
Unknown custom repository
Unknown package source
Unofficial install script
```

Default:

```text
Restricted
```

Yaru dapat menerapkan:

```text
Warn
Require explicit approval
Sandbox
Block
```

berdasarkan policy.

---

# 5. Arsitektur Sistem

```text
                         USER
                           │
                           │
                    paru -S <package>
                           │
                           ▼
                 ┌────────────────────┐
                 │   YARU GATEWAY     │
                 │ Interceptor/Policy │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ SOURCE CLASSIFIER  │
                 └─────────┬──────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
          OFFICIAL       TRUSTED        AUR
          REPO            REPO          ZONE
             │             │             │
             ▼             ▼             ▼
         FAST PATH     TRUST PATH    FULL PATH
             │             │             │
             │             │      ┌──────┴─────────┐
             │             │      │                │
             │             │      ▼                ▼
             │             │   INSPECTION      CHANGE ANALYSIS
             │             │      │                │
             │             │      └───────┬────────┘
             │             │              │
             └─────────────┴──────────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │ REPUTATION       │
                   │ ENGINE           │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │ THREAT INTEL     │
                   │ ENGINE           │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │ RISK ENGINE      │
                   └────────┬─────────┘
                            │
                 ┌──────────┼──────────┐
                 │          │          │
                 ▼          ▼          ▼
               ALLOW       WARN       BLOCK
                 │
                 ▼
          ┌──────────────────┐
          │ SANDBOX BUILDER  │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ BEHAVIOR MONITOR │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ FINAL POLICY     │
          └────────┬─────────┘
                   │
             ┌─────┼─────┐
             ▼     ▼     ▼
           ALLOW  WARN  BLOCK
             │
             ▼
           makepkg
             │
             ▼
           pacman
             │
             ▼
           SYSTEM
```

---

# 6. Core Components

## 6.1 Yaru Gateway

Fungsi:

- Mendeteksi package source
- Menentukan trust zone
- Menjalankan policy
- Memanggil engine yang diperlukan
- Menghubungkan Yaru dengan `paru`, `makepkg`, dan `pacman`

Gateway harus transparan terhadap workflow user.

Target pengalaman:

```bash
paru -S package
```

bukan:

```bash
yaru --inspect --scan --sandbox --...
```

User tetap menggunakan `paru` secara normal.

---

# 7. Package Source Classifier

Input:

```text
Package name
Repository
AUR metadata
Pacman metadata
Paru metadata
```

Output:

```text
OFFICIAL
TRUSTED
THIRD_PARTY
AUR
UNKNOWN
```

Contoh:

```text
firefox
→ extra
→ OFFICIAL
→ Fast Path
```

```text
some-package
→ aur
→ AUR
→ Full Path
```

---

# 8. Package Snapshot

Setiap AUR package yang dianalisis perlu dibuat snapshot.

Minimal menyimpan:

```text
package_name
version
epoch
pkgrel
maintainer
co-maintainers
PKGBUILD hash
.install hash
source URLs
source checksums
dependencies
makedepends
checkdepends
optdepends
AUR metadata
timestamp
```

Snapshot digunakan untuk:

- change detection
- historical analysis
- incident investigation
- reproducibility
- rollback of trust decisions

Database lokal dapat menggunakan SQLite untuk MVP.

---

# 9. Maintainer Change Detection

Yaru harus mendeteksi:

```text
Maintainer Added
Maintainer Removed
Maintainer Changed
Co-maintainer Changed
Ownership Transfer
Orphaned → Adopted
```

Contoh output:

```text
SUPPLY-CHAIN CHANGE DETECTED

Package      : example
Previous     : maintainer-A
Current      : maintainer-B

Risk Impact  : +30
```

Perubahan maintainer tidak otomatis berarti malicious.

Perubahan harus dikorelasikan dengan:

- PKGBUILD changes
- source changes
- dependency changes
- repository history
- reputation
- threat intelligence

---

# 10. PKGBUILD Static Analysis Engine

Engine harus melakukan semantic analysis, bukan sekadar text grep.

Target:

```text
PKGBUILD
.install
shell snippets
build scripts
helper scripts
patch scripts
```

Detection category:

### Remote Execution

Contoh pola risiko:

```bash
curl ... | bash
wget ... | sh
eval "$(curl ...)"
```

### Obfuscation

Deteksi:

```text
base64
hex encoding
compressed payload
string concatenation
dynamic shell generation
indirect execution
```

### Suspicious Execution

Deteksi:

```text
bash -c
sh -c
python -c
perl -e
eval
exec
```

### Persistence / Privilege

Deteksi:

```text
systemd service creation
cron manipulation
sudo configuration
setuid manipulation
shell startup modification
```

### Credential / Sensitive Access

Deteksi akses terhadap:

```text
~/.ssh
~/.config
browser profiles
credential stores
environment secrets
```

Detection harus mempertimbangkan konteks.

Contoh:

```text
curl + GitHub source download
```

tidak otomatis malicious.

Sedangkan:

```text
curl unknown-domain
    ↓
download script
    ↓
chmod +x
    ↓
execute
```

memiliki severity sangat tinggi.

---

# 11. Obfuscation Analyzer

Static analyzer harus dapat melakukan limited deobfuscation untuk:

```text
base64
hex
printf escapes
gzip/xz pipelines
simple string concatenation
encoded shell fragments
```

Tujuan:

```text
Encoded Payload
      ↓
Normalize
      ↓
Decode
      ↓
Analyze
```

Tidak perlu menjalankan payload pada host.

---

# 12. Dependency Scanner

Yaru harus membuat dependency graph.

```text
Package
├── Dependency A
│   └── Dependency C
├── Dependency B
│   └── Dependency D
└── Dependency E
```

Scan minimal:

```text
depends
makedepends
checkdepends
AUR dependencies
transitive dependencies
```

Risk yang dicari:

- dependency baru
- dependency AUR baru
- dependency dengan trust rendah
- dependency maintainer berubah
- dependency memiliki threat IOC
- dependency memiliki static-analysis finding

Output:

```text
Dependency Risk: HIGH

Cause:
- New AUR dependency
- Maintainer changed
- Suspicious PKGBUILD behavior
```

---

# 13. Reputation Engine

Reputation bukan satu angka tunggal.

Komponen:

```text
Package Reputation
Maintainer Reputation
Source Reputation
Repository Reputation
Historical Stability
```

Contoh:

```text
PACKAGE REPUTATION
------------------
Package        92
Maintainer     96
Source         98
History        94
```

Yaru harus menyimpan confidence.

Contoh:

```text
Trust Score: 94
Confidence: High
```

Trust score hanya membantu risk engine dan tidak menjadi satu-satunya keputusan.

---

# 14. Threat Intelligence Engine

Yaru menggunakan IOC database.

IOC types:

```text
Package
Maintainer
Domain
URL
IP
Hash
Repository
Source archive
```

Database dapat memiliki:

```text
indicator
type
severity
confidence
first_seen
last_seen
source
status
```

Contoh:

```text
Indicator:
evil.example

Type:
domain

Status:
malicious

Confidence:
0.98
```

Yaru harus mendukung:

```text
Local IOC database
Remote feed
Community feed
Manual user IOC
```

Threat intelligence harus dapat dinonaktifkan untuk environment offline.

---

# 15. Risk Scoring Engine

Risk engine menggabungkan signal.

Konseptual:

```text
Risk =
    Static Risk
  + Change Risk
  + Dependency Risk
  + Reputation Risk
  + Threat Intelligence Risk
  + Behavioral Risk
```

Setiap komponen mempunyai bobot configurable.

Contoh:

```text
Static Score        0 - 100
Change Score        0 - 100
Dependency Score    0 - 100
Threat Score        0 - 100
Behavior Score      0 - 100
```

Jangan mengandalkan trust score saja.

---

# 16. Risk Levels

Default policy:

```text
0 - 29
LOW

30 - 59
MEDIUM

60 - 79
HIGH

80 - 100
CRITICAL
```

Policy response:

```text
LOW
→ ALLOW

MEDIUM
→ WARN

HIGH
→ REVIEW / QUARANTINE

CRITICAL
→ BLOCK
```

Threshold harus dapat dikonfigurasi.

---

# 17. Sandbox Builder

Semua package AUR berisiko tinggi sebaiknya dibangun di sandbox.

Tujuan:

```text
Contain build scripts
Contain filesystem access
Contain process execution
Contain network access
```

Teknologi target dapat berupa:

```text
bubblewrap
systemd-nspawn
namespaces
seccomp
cgroups
tmpfs
```

Implementasi MVP dapat memilih satu backend utama dahulu.

---

# 18. Network Isolation

Default:

```text
BUILD NETWORK = DENY
```

Masalah:

Beberapa package perlu mengunduh source saat build.

Maka Yaru harus membedakan:

```text
Declared Source
```

dengan:

```text
Unexpected Network Activity
```

Contoh:

```text
Declared:
github.com/project/source.tar.gz

Actual:
github.com/project/source.tar.gz
→ expected

Actual:
unknown-domain.example/payload.sh
→ suspicious
```

Behavior Monitor harus dapat mencatat:

```text
DNS
destination domain
destination IP
port
process
timestamp
```

---

# 19. Sandbox Network Policy

Default modes:

## Strict

```text
No network
```

## Source-Allowlist

```text
Only declared source domains
```

## Audit

```text
Network allowed
All traffic logged
No automatic block
```

## Custom

User dapat membuat policy sendiri.

---

# 20. Behavior Monitor

Setelah static analysis selesai, package dapat diuji dalam sandbox.

Monitor:

### Process

```text
fork
exec
process tree
unexpected binaries
shell spawning
```

### Network

```text
DNS
TCP
UDP
HTTP
HTTPS
unexpected destinations
```

### Filesystem

```text
create
modify
delete
chmod
symlink
```

### Privilege

```text
setuid
setgid
capabilities
sudo attempts
```

Behavior result:

```text
Expected:
gcc
make
cmake

Suspicious:
curl
unknown binary
connection to unknown domain
```

---

# 21. Quarantine

Selain:

```text
ALLOW
WARN
BLOCK
```

Yaru memiliki:

```text
QUARANTINE
```

Quarantine berarti package belum dipercaya untuk masuk ke system, tetapi masih dapat diperiksa dalam sandbox.

Contoh:

```text
Risk Score: 67

VERDICT:
QUARANTINE

Reason:
- Maintainer changed
- Network behavior requires review
```

User dapat melakukan:

```text
Review
Approve
Reject
```

---

# 22. Final Policy Engine

Policy engine adalah decision layer terakhir.

Input:

```text
trust
static findings
maintainer changes
dependency findings
IOC findings
behavior findings
user policy
repository trust zone
```

Output:

```text
ALLOW
WARN
QUARANTINE
BLOCK
```

Policy harus deterministic dan explainable.

Yaru wajib menjelaskan kenapa suatu package diblokir.

---

# 23. Explainability

Setiap keputusan harus memiliki evidence.

Contoh:

```text
YARU VERDICT: BLOCK

Reasons:

1. Maintainer changed 1 day ago
2. PKGBUILD introduced remote shell execution
3. Unknown domain detected
4. Encoded payload detected
5. Behavior monitor observed unexpected network activity

Threat Score: 94/100
```

Jangan menampilkan:

```text
BLOCKED: AI says malware
```

AI tidak boleh menjadi satu-satunya decision source.

---

# 24. CLI Design

## Status

```bash
yaru status
```

Menampilkan:

```text
Yaru version
Engine status
Threat intel status
Sandbox backend
Paru integration
Policy
Database
```

---

## Inspect

```bash
yaru inspect <package>
```

Menjalankan analisis tanpa install.

---

## Audit

```bash
yaru audit <package>
```

Analisis mendalam.

---

## Trust

```bash
yaru trust <package>
```

Menampilkan trust model dan history.

---

## History

```bash
yaru history <package>
```

Menampilkan perubahan:

```text
maintainer
PKGBUILD
dependencies
source
risk
```

---

## Explain

```bash
yaru explain <package>
```

Menjelaskan keputusan Yaru.

---

# 25. Paru Integration

Target UX:

```bash
paru -S <package>
```

Yaru otomatis melakukan:

```text
1. Detect package source
2. Determine trust zone
3. Create snapshot
4. Run required inspection
5. Calculate risk
6. Apply policy
7. Sandbox if required
8. Monitor build behavior
9. Recalculate risk
10. Allow/warn/block
11. Continue paru
```

Tidak mengharuskan user mengubah workflow.

---

# 26. Contoh Fast Path

User:

```bash
paru -S firefox
```

Source:

```text
extra
```

Yaru:

```text
SOURCE: OFFICIAL

Signature       PASS
Integrity       PASS
Threat Intel    CLEAN

VERDICT: ALLOW
```

Yaru melewati sandbox AUR.

---

# 27. Contoh AUR Path

User:

```bash
paru -S example-bin
```

Yaru:

```text
SOURCE: AUR

[1/6] Package Snapshot
[2/6] Maintainer Analysis
[3/6] PKGBUILD Analysis
[4/6] Dependency Analysis
[5/6] Reputation / Threat Intel
[6/6] Risk Evaluation
```

Hasil:

```text
Trust Score: 91
Risk Score : 12

VERDICT: ALLOW
```

Kemudian package dibangun.

---

# 28. Contoh Suspicious Package

```text
SOURCE: AUR

Trust Score       32
Static Score      82
Change Score      71
Dependency Score  46
Threat Score      15
```

Risk:

```text
HIGH
```

Yaru:

```text
VERDICT: QUARANTINE
```

Sandbox build dilakukan.

Behavior:

```text
Unexpected DNS request
Unknown executable downloaded
```

Risk naik:

```text
HIGH → CRITICAL
```

Final:

```text
VERDICT: BLOCK
```

---

# 29. Data Model

MVP dapat menggunakan SQLite.

Contoh tabel:

```text
packages
package_versions
maintainers
package_maintainers
package_sources
dependencies
package_snapshots
package_changes
threat_indicators
reputation_scores
scan_results
behavior_events
policy_decisions
```

---

# 30. Event Model

Setiap event keamanan disimpan sebagai event.

Contoh:

```json
{
  "type": "maintainer_changed",
  "package": "example",
  "old": "alice",
  "new": "bob",
  "severity": "medium"
}
```

Behavior:

```json
{
  "type": "network_connection",
  "package": "example",
  "process": "curl",
  "destination": "unknown.example",
  "expected": false,
  "severity": "high"
}
```

---

# 31. Rule Engine

Static dan behavior detection sebaiknya memakai rule engine yang dapat diperbarui tanpa recompiling core Yaru.

Contoh konsep:

```yaml
id: remote-shell-download
category: execution
severity: critical

conditions:
  - network_download
  - shell_execution
  - remote_source

score: 80
```

Rule harus memiliki:

```text
id
name
description
category
severity
conditions
score
references
enabled
```

---

# 32. Security Architecture

Yaru sendiri harus mengikuti prinsip least privilege.

Komponen:

```text
Yaru CLI
    ↓
Analysis Service
    ↓
Sandbox Worker
```

Jangan menjalankan seluruh Yaru sebagai root.

Root privilege hanya diberikan kepada komponen yang benar-benar membutuhkan privilege.

Target:

```text
CLI              → user
Analyzer         → user
Database         → user
Sandbox worker   → restricted user
Privileged hook  → minimal privilege
```

---

# 33. Failure Handling

Jika Yaru gagal:

Contoh:

```text
Threat Intel unavailable
```

default policy:

```text
Tidak otomatis menjadi BLOCK
```

Harus ada mode:

```text
fail-open
fail-closed
```

Default untuk AUR security mode dapat dipilih user.

Contoh:

```yaml
policy:
  on_engine_failure: warn
```

Untuk environment high-security:

```yaml
policy:
  on_engine_failure: block
```

---

# 34. Offline Mode

Yaru harus tetap bisa bekerja tanpa internet.

Offline features:

```text
PKGBUILD scanning
dependency analysis
local reputation
local snapshot comparison
local IOC database
sandbox
behavior monitoring
```

Remote features:

```text
AUR metadata refresh
Threat intelligence feed
community reputation
remote update feed
```

---

# 35. False Positive Management

Yaru harus memungkinkan:

```bash
yaru allow-rule <rule>
```

atau policy exception.

Contoh:

```text
Known safe build process triggers curl
```

User dapat membuat exception berdasarkan:

```text
package
version
rule
source
domain
process
```

Exception harus jelas dan tercatat.

---

# 36. Security Logging

Log Yaru harus menyimpan:

```text
timestamp
package
version
source
trust zone
rule
finding
risk score
decision
user override
sandbox result
```

Format dapat berupa:

```text
JSON Lines
```

agar mudah diproses oleh:

```text
jq
SIEM
Grafana
OpenSearch
ELK
```

---

# 37. IDS / IPS Classification

Yaru dapat dipetakan ke model IDS/IPS seperti berikut:

```text
                 YARU
                  │
        ┌─────────┴─────────┐
        │                   │
       IDS                 IPS
        │                   │
        ▼                   ▼
Detect                  Enforce
        │                   │
        ├─ PKGBUILD         ├─ BLOCK
        ├─ Maintainer       ├─ WARN
        ├─ Dependency       ├─ QUARANTINE
        ├─ Threat Intel     └─ ALLOW
        └─ Behavior
```

IDS:

```text
"Ini mencurigakan."
```

IPS:

```text
"Jangan izinkan package ini melanjutkan."
```

---

# 38. Project Structure

Rekomendasi awal:

```text
yaru/
├── cmd/
│   └── yaru/
│
├── core/
│   ├── classifier/
│   ├── analyzer/
│   ├── reputation/
│   ├── dependency/
│   ├── threatintel/
│   ├── risk/
│   └── policy/
│
├── interceptor/
│   ├── paru/
│   ├── makepkg/
│   └── pacman/
│
├── sandbox/
│   ├── backend/
│   ├── network/
│   ├── filesystem/
│   └── process/
│
├── monitor/
│   ├── network/
│   ├── process/
│   ├── filesystem/
│   └── syscall/
│
├── storage/
│   ├── sqlite/
│   ├── models/
│   └── migrations/
│
├── rules/
│   ├── pkgbuild/
│   ├── shell/
│   └── behavior/
│
├── config/
│
├── cli/
│
└── docs/
```

---

# 39. Recommended Technology

Pilihan utama:

```text
Language:
Rust
```

Alasan:

```text
- native Linux
- low overhead
- memory safety
- good CLI ecosystem
- good process/network primitives
- cocok untuk security tooling
```

Potential libraries/components:

```text
clap
serde
serde_json
tokio
reqwest
rusqlite / sqlx
tracing
tree-sitter
```

Sandbox backend:

```text
bubblewrap
systemd-nspawn
Linux namespaces
seccomp
cgroups
```

Tooling harus dipilih berdasarkan kebutuhan implementasi nyata, bukan hanya popularitas library.

---

# 40. AI / ML Usage

AI bukan decision maker utama.

AI dapat digunakan sebagai:

```text
Secondary Analysis
```

Contoh:

```text
Static Findings
+
Diff
+
Behavior Events
        ↓
AI Explanation / Triage
```

AI boleh membantu menjawab:

```text
"Mengapa pattern ini mencurigakan?"
```

Tetapi policy harus tetap deterministic.

Arsitektur:

```text
Deterministic Engine
        ↓
Risk
        ↓
Policy
        ↓
Allow/Warn/Block

AI
  └── optional explanation / triage
```

---

# 41. Development Roadmap

## Phase 1: MVP

Implement:

```text
✓ CLI
✓ Package source detection
✓ AUR detection
✓ PKGBUILD scanner
✓ Basic trust score
✓ Maintainer snapshot
✓ Maintainer change detection
✓ SQLite
✓ Allow/Warn/Block
```

Belum perlu:

```text
advanced sandbox
behavior monitoring
remote threat feed
AI
```

---

## Phase 2: Supply-Chain Security

Tambah:

```text
✓ Dependency graph
✓ PKGBUILD diff
✓ Source diff
✓ Reputation history
✓ Threat IOC database
✓ Package history
```

---

## Phase 3: Sandbox

Tambah:

```text
✓ build isolation
✓ filesystem isolation
✓ network isolation
✓ process monitoring
```

---

## Phase 4: Behavioral IDS

Tambah:

```text
✓ DNS monitoring
✓ network destination tracking
✓ process tree
✓ filesystem events
✓ syscall events
✓ dynamic risk update
```

---

## Phase 5: Paru Integration

Tujuan:

```text
paru -S package
```

menjadi workflow:

```text
paru
 ↓
Yaru
 ↓
Security Decision
 ↓
Build / Install
```

---

# 42. Acceptance Criteria

Yaru MVP dianggap berhasil jika:

### Package Source

```text
✓ Bisa membedakan official repo vs AUR
✓ Bisa menerapkan trust zone
```

### AUR

```text
✓ Bisa membaca PKGBUILD
✓ Bisa membaca .install
✓ Bisa mendeteksi suspicious patterns
✓ Bisa menyimpan package snapshot
```

### Supply Chain

```text
✓ Bisa mendeteksi maintainer change
✓ Bisa mendeteksi PKGBUILD diff
✓ Bisa mendeteksi dependency change
```

### Risk

```text
✓ Bisa menghasilkan risk score
✓ Bisa menjelaskan evidence
✓ Bisa menerapkan policy
```

### Integration

```text
✓ Tidak merusak workflow paru
✓ Bisa melakukan dry-run
✓ Bisa digunakan tanpa internet
```

---

# 43. Non-Goals

Yaru tidak ditujukan untuk:

```text
❌ menggantikan pacman
❌ menggantikan paru
❌ menjadi antivirus sistem penuh
❌ menjamin package 100% aman
❌ menjalankan semua package dalam sandbox berat
❌ menggunakan AI sebagai malware oracle
```

Yaru fokus pada:

```text
AUR/package supply-chain risk
```

---

# 44. Final Architecture

Arsitektur target Yaru:

```text
                         PARU
                          │
                          ▼
                  ┌──────────────┐
                  │ YARU GATEWAY │
                  └──────┬───────┘
                         │
                         ▼
                 SOURCE CLASSIFIER
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
       OFFICIAL       TRUSTED          AUR
          │              │              │
       FAST PATH     TRUST PATH      FULL PATH
          │              │              │
          │              │        ┌─────┴─────┐
          │              │        │           │
          │              │        ▼           ▼
          │              │     STATIC      CHANGE
          │              │     ANALYSIS    ANALYSIS
          │              │        │           │
          │              │        └─────┬─────┘
          │              │              │
          │              └──────────────┤
          │                             ▼
          │                      DEPENDENCY ENGINE
          │                             │
          │                             ▼
          │                      REPUTATION ENGINE
          │                             │
          │                             ▼
          │                       THREAT INTEL
          │                             │
          └─────────────────────────────┤
                                        ▼
                                  RISK ENGINE
                                        │
                         ┌──────────────┼──────────────┐
                         ▼              ▼              ▼
                       ALLOW           WARN           BLOCK
                         │
                         ▼
                     SANDBOX
                         │
                         ▼
                  BEHAVIOR MONITOR
                         │
                         ▼
                    RISK UPDATE
                         │
                         ▼
                  FINAL POLICY
                         │
                  ┌──────┼──────┐
                  ▼      ▼      ▼
                ALLOW   WARN   BLOCK
                  │
                  ▼
                MAKEPKG
                  │
                  ▼
                PACMAN
                  │
                  ▼
                SYSTEM
```

---

# 45. Design Philosophy

Yaru harus mengikuti tiga prinsip:

## Principle 1

> **Trust less, verify more.**

## Principle 2

> **Static analysis first, containment second, enforcement last.**

## Principle 3

> **Evidence decides policy, not package popularity alone.**

Target akhirnya bukan membuat AUR terasa seperti repository resmi.

Target Yaru adalah membuat:

```text
AUR
+
Visibility
+
Verification
+
Containment
+
Policy
```

menjadi workflow yang aman dan tetap nyaman untuk pengguna Arch.

---

# 46. Instruksi untuk Build Agent

Build agent yang mengimplementasikan Yaru harus memahami konteks berikut:

1. Yaru adalah security layer untuk Arch Linux.
2. Fokus utama adalah AUR supply-chain security.
3. Repository resmi tidak perlu melewati full AUR pipeline.
4. AUR harus melewati full inspection sesuai risk policy.
5. Maintainer change adalah signal, bukan bukti malware.
6. Trust score bukan keputusan final.
7. Risk engine harus menggabungkan banyak signal.
8. Static analysis harus memeriksa konteks, bukan sekadar grep.
9. Build berisiko harus dapat diisolasi menggunakan sandbox.
10. Network isolation harus menjadi komponen utama security model.
11. Behavior analysis dapat menaikkan atau menurunkan risk.
12. Semua keputusan harus explainable.
13. AI hanya boleh menjadi secondary analysis/triage, bukan satu-satunya malware detector.
14. Yaru tidak boleh menggantikan `pacman` atau `paru`.
15. Prioritaskan MVP yang kecil, deterministic, testable, dan dapat diperluas.

Build agent harus menghindari implementasi yang:

```text
- terlalu bergantung pada AI
- menganggap semua AUR package malicious
- memblokir hanya berdasarkan satu heuristic lemah
- memaksa sandbox berat untuk setiap official package
- menjalankan analyzer dengan root tanpa kebutuhan
- mengubah behavior pacman/paru secara tidak transparan
```

End goal:

```text
paru
  ↓
Yaru
  ↓
Inspect
  ↓
Score
  ↓
Contain
  ↓
Decide
  ↓
Build
  ↓
Install
```

**Yaru = AUR Supply-Chain IDS/IPS for Arch Linux.**
