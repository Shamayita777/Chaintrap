# ChainTrap v2

**Ransomware Detection & Protection System**  
*Patent-Pending · Cross-Platform · Blockchain-Anchored Forensic Audit Trail*

---

## Overview

ChainTrap v2 is a production-grade, behavior-based ransomware detection engine. Unlike signature-based AV which requires known malware hashes, ChainTrap detects ransomware activity by observing *what files do* — not what they are.

**Key capabilities:**

| Layer | What it does |
|-------|-------------|
| **Multi-signal entropy engine** | Detects encrypted file content using Shannon entropy, chi-squared randomness test, magic-byte validation, sliding-window analysis, and entropy delta tracking |
| **Dynamic honeyfiles** | Deploys realistic, attractive decoy files (valid OOXML, PDFs with plausible names and sizes). A single decoy access triggers immediate lockdown |
| **Canary token network** | Embeds HTTP callback URLs in decoy files. When ransomware opens a file, the callback fires *before* encryption begins |
| **Burst detectors** | Two independent detectors: `NewFileBurstTracker` (rename-and-re-encrypt) and `BurstAccumulator` (slow encryption over minutes) |
| **Blockchain audit trail** | Every event is appended to a SHA-256 linked chain. Supports local, webhook, and IPFS replication modes |
| **Forensic REST API** | Live dashboard, paginated chain viewer, event log with filters, one-click quarantine and network lockdown |
| **Evaluation framework** | 6 benchmark profiles covering all major evasion vectors, with precision/recall/F1/FPR/FNR metrics and latency percentiles |

---

## Architecture

```
ChainTrap v2
├── core/
│   ├── entropy_analyzer.py    — 4-signal detection pipeline
│   ├── monitor.py             — Watchdog-based filesystem monitor
│   ├── decoy_manager.py       — Dynamic honeyfile generation
│   ├── canary_server.py       — Canary token server + embedder
│   ├── blockchain_logger.py   — Tamper-evident audit chain
│   ├── event_logger.py        — JSONL structured event log
│   └── platform_ops.py        — Cross-platform quarantine/lockdown
├── api/
│   └── dashboard.py           — REST API + HTML5 forensic dashboard
├── eval/
│   └── benchmark.py           — Evaluation & benchmarking framework
├── config/
│   └── config.py              — Cross-platform config resolver
├── tests/                     — 100+ pytest unit tests
├── main.py                    — CLI entry point
└── .github/workflows/ci.yml   — CI/CD pipeline (6 jobs, 3 OS)
```

---

## Quick Start

### Installation

```bash
git clone https://github.com/your-org/chaintrap.git
cd chaintrap
pip install -r requirements.txt
```

### Start monitoring

```bash
python main.py
```

ChainTrap will:
1. Deploy honeyfiles in configured decoy directories
2. Seed entropy baselines for all monitored files
3. Start the filesystem watchdog (inotify/FSEvents/ReadDirectoryChangesW)
4. Begin recording events to the blockchain

### Useful commands

```bash
python main.py --test          # Run detection self-test
python main.py --verify        # Verify blockchain integrity
python main.py --chain         # Print last 20 blockchain blocks
python main.py --events 50     # Show last 50 events
python main.py --config        # Write default config template
```

---

## Configuration

Edit `chaintrap.json` (created on first run or via `--config`):

```json
{
  "decoy_dirs":                ["/Users/you/Documents/decoys"],
  "protected_dirs":            ["/Users/you/Documents"],
  "entropy_absolute_threshold": 7.2,
  "entropy_delta_threshold":    1.5,
  "burst_window_seconds":       60,
  "burst_event_threshold":      5,
  "blockchain_mode":            "dual",
  "webhook_url":                "https://your-server.com/chain/ingest",
  "email_alerts":               false
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `entropy_absolute_threshold` | `7.2` | Shannon entropy above this = suspicious |
| `entropy_delta_threshold` | `1.5` | Entropy jump above this = suspicious |
| `burst_window_seconds` | `60` | Sliding window for burst detection |
| `burst_event_threshold` | `5` | Events in window to trigger burst alert |
| `blockchain_mode` | `"local"` | `local`, `webhook`, `dual`, or `ipfs` |

---

## REST API Dashboard

Start the forensic dashboard:

```bash
python -m api.dashboard --port 5000
# or with auth:
CHAINTRAP_API_KEY=your-secret python -m api.dashboard --port 5000
```

Open `http://localhost:5000` for the live dashboard.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | HTML5 forensic dashboard |
| `GET` | `/api/status` | System status (always public) |
| `GET` | `/api/chain` | Paginated blockchain (`?page=1&limit=50`) |
| `GET` | `/api/chain/{n}` | Single block by index |
| `GET` | `/api/chain/verify` | Chain integrity check |
| `GET` | `/api/events` | Event log (`?type=&severity=&since=`) |
| `GET` | `/api/canary/status` | Canary token status |
| `POST` | `/api/response/quarantine` | Quarantine a file `{"path": "/..."}`  |
| `POST` | `/api/response/lockdown` | Network lockdown |

Auth: `Authorization: Bearer <CHAINTRAP_API_KEY>` (if key is set).

---

## Canary Token System

### Self-hosted mode

```bash
# Start canary server
python -m core.canary_server serve --host 0.0.0.0 --port 8765

# Embed tokens in decoy files
python -m core.canary_server embed /path/to/decoy.docx /path/to/decoy2.txt

# Check status
python -m core.canary_server status
```

### Programmatic use

```python
from core.canary_server import CanaryManager

def on_ransomware(token):
    print(f"🚨 Ransomware detected! File: {token.decoy_path}, IP: {token.trigger_ip}")

mgr = CanaryManager(host="0.0.0.0", port=8765, on_trigger=on_ransomware)
mgr.start()
mgr.embed_in_all_decoys(decoy_paths)
```

### Embedding strategies by file type

| File type | Embedding method | Trigger condition |
|-----------|-----------------|-------------------|
| `.docx/.xlsx/.pptx` | External hyperlink relationship in `_rels/` | Opened by any process traversing hyperlinks |
| `.pdf` | `/OpenAction /URI` | Opened by any PDF reader |
| `.txt/.csv/.py` | Plaintext URL in footer | Ransomware string-scanning recon pass |

---

## Benchmark Framework

Run the full evaluation suite:

```bash
# All profiles
python -m eval.benchmark --profile all --output results/benchmark.json

# Specific profile with verbose output
python -m eval.benchmark --profile ransomware_fpe --verbose

# Quick run
python -m eval.benchmark --profile ransomware_fast --n-malicious 20
```

### Benchmark profiles

| Profile | Simulates | Ground truth |
|---------|-----------|-------------|
| `benign_office` | Word/Excel saves, text edits | No detection expected |
| `ransomware_fast` | 100 files encrypted in <5s (LockBit-style) | Detection expected |
| `ransomware_slow` | 3 files/minute (slow-burn evasion) | Detection expected |
| `ransomware_fpe` | Format-preserving encryption (valid ZIP header) | Detection expected |
| `ransomware_b64` | Base64-encoded ciphertext (~6.0 entropy) | Detection expected |
| `ransomware_partial` | First 4KB encrypted, rest normal | Detection expected |

### Metrics reported

- **Precision** — of files flagged, % actually malicious
- **Recall** — of malicious files, % detected  
- **F1** — harmonic mean of precision and recall
- **FPR** — false positive rate on benign workload
- **FNR** — false negative rate on malicious workload
- **Latency p50/p95** — detection latency in milliseconds
- **Throughput** — events/second the engine sustains
- **CPU/Memory overhead** — system resource impact

---

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Skip slow tests
pytest tests/ -v -m "not slow"

# With coverage
pytest tests/ --cov=core --cov=api --cov=eval --cov-report=html

# Specific test file
pytest tests/test_entropy_analyzer.py -v
```

### Test coverage

| Module | Tests | Coverage areas |
|--------|-------|---------------|
| `test_entropy_analyzer.py` | ~30 tests | All 5 evasion countermeasures, edge cases, performance |
| `test_blockchain_logger.py` | ~25 tests | Block structure, verification, persistence, thread safety |
| `test_decoy_and_canary.py` | ~35 tests | Decoy generation, canary registry, embedder, server, manager |
| `test_dashboard_and_benchmark.py` | ~40 tests | All API endpoints, auth, benchmark metrics, file generators |

---

## Evasion Vectors Addressed

| Vector | Attack description | ChainTrap countermeasure |
|--------|-------------------|--------------------------|
| **Entropy sharing** | Mix encrypted blocks with low-entropy padding to keep global entropy below 6.5 | Sliding-window analysis — detects high-entropy segments even when global is low |
| **Format-Preserving Encryption (FPE)** | Keep valid ZIP/OOXML header, encrypt payload | OOXML ZIP structure validation — checks internal structure, not just 4-byte magic |
| **Decoy-aware ransomware** | Skip files with honeypot names like `aaa_decoy.docx` | Dynamic, realistic decoys with plausible names (50KB–5MB, valid OOXML, canary-embedded) |
| **Rename-and-re-encrypt** | Encrypt file, save as `.enc`, delete original | `NewFileBurstTracker` — detects burst of `.enc`/`.locked` file creations |
| **Slow encryption** | Encrypt 1 file per minute to stay below burst threshold | `BurstAccumulator` — tracks events over 10-minute window |
| **Base64 ciphertext** | Base64-encode ciphertext to reduce entropy to ~6.0 | Chi-squared uniformity test detects non-uniform base64 alphabet distribution |
| **Partial encryption** | Encrypt only first 4KB (file metadata/headers) | Shannon sliding windows — the encrypted segment spikes max-window entropy |

---

## CI/CD Pipeline

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs 6 jobs on every push:

1. **Lint** — Ruff linting + format check + mypy type checking
2. **Test** — Full pytest suite on matrix: 3 OS × 3 Python versions
3. **Benchmark** — Regression check on detection recall (≥60%) and latency (≤500ms p95)
4. **Self-Test** — End-to-end `main.py --test` + `test_part2.py`
5. **Build** — Wheel + sdist via `python -m build`
6. **Security** — `safety` dependency scan + `bandit` static analysis

---

## Threat Model

ChainTrap is designed for:
- **Endpoint protection** on workstations handling sensitive files (finance, legal, healthcare)
- **Honeypot/deception networks** where decoy files are the primary detection layer
- **Forensic audit** where a tamper-evident log of all file activity is required

ChainTrap is **not** a replacement for:
- AV/EDR (no signature scanning)
- Backup solutions (no file recovery)
- Network IDS/IPS (monitors filesystem events only, not network traffic)

---

## License

Proprietary. All rights reserved. Patent pending.

For licensing inquiries, contact the ChainTrap team.
