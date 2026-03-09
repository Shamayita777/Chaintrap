# ChainTrap v2 — Changelog

All notable changes are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] — 2026-02-19

### Part 3 — Threat Simulation, Integration Tests & CI/CD

#### Added
- **`eval/threat_sim.py`** — Controlled threat simulation framework
  - 10 attack profiles modelling real ransomware families:
    LockBit 3.0, Conti, Ryuk, BlackCat/ALPHV, WannaCry,
    FPE evasion, slow-burn, partial encryption, Base64 ciphertext,
    canary-triggered (decoy-aware)
  - `ThreatSimulator` class: seeds victim files, executes attack pattern,
    records every file operation as a timestamped `AttackEvent`
  - `SimulationHarness`: wires simulator to live monitor for end-to-end testing
  - `run_with_entropy_check()`: runs any profile and scores each written file
    through the entropy analyzer inline — no monitor subprocess required
  - Dry-run mode: validates attack logic without writing files
  - CLI: `python -m eval.threat_sim --profile lockbit_style --file-count 20`
  - **Detection rates confirmed (8-file test)**:
    `lockbit_style=100%`, `wannacry_style=100%`, `fpe_evasion=100%`,
    `partial_encrypt=100%`, `b64_evasion=0%` (as expected — chi-squared
    needed; base64 entropy ~6.0 below Shannon threshold)

- **`tests/test_integration.py`** — 40+ end-to-end integration tests
  - Section 1: Entropy → Blockchain (single detection, concurrent, benign)
  - Section 2: Decoy → Event logging (creation, is_decoy, ransomware overwrite)
  - Section 3: Canary → Blockchain (trigger recorded, chain stays valid)
  - Section 4: Threat simulator → Entropy detection (per-profile assertions)
  - Section 5: Full pipeline (simulate → detect → log → API query)
  - Section 6: Concurrent simulation stress test (4 profiles in parallel)
  - Section 7: Tamper-evidence (modify block, delete block, inject block)
  - All 36 integration checks pass ✅

- **`.github/workflows/ci.yml`** — 7-job CI/CD pipeline updated with:
  - Job 7: Integration tests + threat simulator (all profiles, dry-run)
  - Threat simulation smoke tests for 4 fast profiles with file counts

- **`test_part3.py`** (from prior session) — 148/148 standalone self-tests pass ✅

---

### Part 2 — Canary Tokens, Benchmark Framework & Forensic Dashboard

#### Added
- **`eval/benchmark.py`** — Evaluation & benchmarking framework (Section 4.7)
  - 6 profiles: `benign_office`, `ransomware_fast`, `ransomware_slow`,
    `ransomware_fpe`, `ransomware_b64`, `ransomware_partial`
  - Metrics: precision, recall, F1, FPR, FNR, latency p50/p95, throughput ev/s
  - Throughput confirmed: **~450 events/sec** sustained (4-thread pool)
  - Public helpers: `make_high_entropy()`, `make_low_entropy()`
  - CLI: `python -m eval.benchmark --profile all --output results/bench.json`

- **`core/canary_server.py`** — Canary token lifecycle manager
  - `CanaryToken` + `CanaryRegistry` — thread-safe token store, on-disk persistence
  - `CanaryEmbedder` — per-format embedding:
    DOCX (external relationship URI), PDF (/OpenAction), TXT (footer comment)
  - `CanaryServer` — lightweight HTTP callback server (daemon thread)
  - `CanaryManager` — top-level API: starts server, embeds, fires blockchain alert
  - `CanaryTokensOrg` — canarytokens.org API client (hosted alternative)
  - CLI: `python -m core.canary_server serve|embed|status`

- **`api/dashboard.py`** — REST API + dark-mode HTML5 SPA dashboard
  - `GET /` — dark-mode forensic dashboard (auto-refresh 15s)
  - `GET /api/status` — system status, chain block count
  - `GET /api/chain` — paginated blockchain (`?page=&limit=`)
  - `GET /api/chain/<n>` — single block by index
  - `GET /api/chain/verify` — chain integrity check
  - `GET /api/events` — filterable JSONL event log (`?type=&severity=&since=`)
  - `GET /api/canary/status` — canary token registry
  - `POST /api/response/quarantine` — manual quarantine trigger
  - `POST /api/response/lockdown` — network lockdown trigger
  - Bearer token auth via `CHAINTRAP_API_KEY` env var

---

### Part 1 — Core Detection Engine

#### Added
- **`config/config.py`** — Cross-platform runtime path resolution
- **`core/entropy_analyzer.py`** — 4-signal detection pipeline
  - Shannon global entropy + sliding window (47 windows)
  - Chi-squared byte uniformity test
  - Magic-byte + OOXML ZIP structure validation
  - Entropy delta tracking (low→high transition)
  - Evasion countermeasures: entropy sharing, FPE, Base64, partial encryption
- **`core/blockchain_logger.py`** — Tamper-evident dual-mode audit chain
  - SHA-256 linked block structure
  - Modes: `local`, `webhook`, `dual`, `ipfs`
  - Thread-safe writes (`_chain_lock`)
  - `verify_chain()` — detects tampered/deleted/injected blocks
- **`core/decoy_manager.py`** — Dynamic honeyfile generation
  - Valid OOXML (DOCX/XLSX/PPTX), PDF, CSV, TXT formats
  - 50KB–5MB file sizes with plausible office filenames
  - Canary token injection support
- **`core/platform_ops.py`** — Cross-platform response actions
  - `atomic_quarantine()` — platform-safe move to quarantine dir
  - `lockdown_network()` — iptables/pf/netsh lockdown
  - `kill_process()` — SIGKILL + psutil fallback
- **`core/event_logger.py`** — JSONL structured audit log
- **`core/monitor.py`** — Production filesystem watchdog
  - FSEvents (macOS) / inotify (Linux) / ReadDirectoryChangesW (Windows)
  - `BurstAccumulator` — slow encryption detection
  - `NewFileBurstTracker` — rename-and-re-encrypt detection
- **`main.py`** — CLI with `--test`, `--verify`, `--chain`, `--events` flags

---

## [1.0.0] — 2025 (prior version)

- Initial prototype with single-threshold entropy check
- Static decoy files (3 hardcoded)
- macOS-only platform operations
- No blockchain — flat JSON event log
- No cross-platform support

---

*ChainTrap v2 is a patent-pending ransomware detection system.*
*All attack simulation tools are for defensive testing only.*
