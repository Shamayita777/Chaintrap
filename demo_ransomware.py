#!/usr/bin/env python3
"""
ChainTrap Demo — Ransomware Simulator
======================================
This is the ATTACKER script for the India Innovates demo.

It simulates a real ransomware attack:
  1. Creates realistic-looking documents (AIIMS patient file, NIC brief, etc.)
  2. Encrypts them one-by-one with real AES-style random bytes
  3. Renames them with .locked extension
  4. Touches a canary/honeyfile to trigger that tripwire

Your ChainTrap engine (running in background) will detect this
and post events to /api/events and /api/chain.

The dashboard at http://localhost:5000 will light up red in real time.

Usage:
  # Fast attack (LockBit-style, 6 files in ~4 seconds):
  python demo_ransomware.py --mode fast

  # Slow attack (evasion-style, 1 file every 3 seconds):
  python demo_ransomware.py --mode slow

  # Target a specific directory:
  python demo_ransomware.py --mode fast --target /path/to/folder

  # Reset: remove all .locked files from last demo:
  python demo_ransomware.py --reset
"""

import os
import sys
import time
import random
import shutil
import struct
import secrets
import argparse
import tempfile
from pathlib import Path

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
AMBER  = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗         ║
║  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║         ║
║  ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║         ║
║  ██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║         ║
║  ██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║         ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝         ║
║                                                                  ║
║  ChainTrap DEMO — Ransomware Simulator                           ║
║  ⚠  FOR DEMONSTRATION PURPOSES ONLY                              ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")

# ── Realistic file content (low entropy baselines) ────────────────────────────

FAKE_DOCX_CONTENT = (
    b"PK\x03\x04" +   # ZIP magic (OOXML is a ZIP)
    b"\x14\x00\x00\x00\x08\x00" +
    b"AIIMS Patient Record System\n" * 120 +
    b"Patient ID: AIIMS-2024-" +
    b"Dr. Ramesh Kumar, HOD Cardiology\n" * 80 +
    b"Confidential Medical Record\n" * 100
)

FAKE_XLSX_CONTENT = (
    b"PK\x03\x04" +
    b"\x14\x00\x00\x00\x08\x00" +
    b"Ministry of Health Budget 2026\n" * 100 +
    b"Department,Allocation,Utilised\n" * 80 +
    b"AIIMS Delhi,2400 Cr,1890 Cr\n" * 60
)

FAKE_PDF_CONTENT = (
    b"%PDF-1.7\n" +
    b"National Informatics Centre - Confidential Brief\n" * 100 +
    b"Subject: Cybersecurity Policy for Government Systems\n" * 80 +
    b"Classification: SECRET\n" * 120
)

FAKE_TXT_CONTENT = (
    b"NIC Server Access Credentials\n" +
    b"================================\n" +
    b"Server: nic-prod-01.gov.in\n" +
    b"Port: 22\n" +
    b"Notes: Production database server - DO NOT SHARE\n" +
    b"Backup key location: /secure/vault/backup.key\n" * 80
)

# File templates: (filename, content, extension)
FILE_TEMPLATES = [
    ("AIIMS_Patient_Records_2024", FAKE_DOCX_CONTENT, ".docx"),
    ("NIC_Ministry_Brief_Confidential", FAKE_PDF_CONTENT, ".pdf"),
    ("MoH_Budget_Allocation_2026", FAKE_XLSX_CONTENT, ".xlsx"),
    ("Server_Access_Credentials", FAKE_TXT_CONTENT, ".txt"),
    ("CERT-In_Incident_Report_Q4", FAKE_PDF_CONTENT, ".pdf"),
    ("Government_Tender_Final_Signed", FAKE_DOCX_CONTENT, ".docx"),
    ("NIC_Infrastructure_Audit", FAKE_XLSX_CONTENT, ".xlsx"),
    ("PM_Office_Brief_March2026", FAKE_PDF_CONTENT, ".pdf"),
]

CANARY_NAMES = [
    "~aaa_backup_important.docx",
    "~passwords_backup.txt",
    "~admin_credentials.xlsx",
]

def encrypt_bytes(data: bytes) -> bytes:
    """
    Simulate ransomware encryption:
    XOR with random key (produces near-max Shannon entropy ~7.9 bits/byte)
    In real ransomware this would be AES-128/256.
    """
    key = secrets.token_bytes(32)
    encrypted = bytearray()
    for i, b in enumerate(data):
        encrypted.append(b ^ key[i % len(key)] ^ (i & 0xFF))
    return bytes(encrypted)

def log(icon, colour, msg):
    ts = time.strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {colour}{icon}  {msg}{RESET}")

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK MODES
# ═══════════════════════════════════════════════════════════════════════════════

def run_attack(target_dir: Path, mode: str):
    """
    Main attack sequence.
    Creates real files then overwrites them with encrypted content.
    """
    print(f"\n{RED}{BOLD}▶ ATTACK INITIATED — MODE: {mode.upper()}{RESET}\n")
    print(f"{DIM}  Target directory: {target_dir}{RESET}")
    print(f"{DIM}  ChainTrap should detect this within seconds.{RESET}\n")

    target_dir.mkdir(parents=True, exist_ok=True)

    delays = {
        'fast': 0.5,   # LockBit-style: fast mass encryption
        'slow': 3.0,   # Evasion-style: slow, stays under burst threshold
    }
    delay = delays.get(mode, 0.5)

    created_files = []

    # ── PHASE 1: Create decoy (canary) files ────────────────────────────────
    log("🎯", AMBER, "Phase 1: Dropping canary-detection probe...")
    time.sleep(0.5)

    canary_path = target_dir / random.choice(CANARY_NAMES)
    canary_path.write_bytes(b"This is a backup file - do not delete\n" * 50)
    log("📁", AMBER, f"Canary file created: {canary_path.name}")
    time.sleep(0.3)

    # ── PHASE 2: Create realistic victim files ───────────────────────────────
    log("📂", CYAN, "Phase 2: Creating victim files (simulating existing documents)...")
    time.sleep(0.5)

    templates = random.sample(FILE_TEMPLATES, min(6, len(FILE_TEMPLATES)))
    for name, content, ext in templates:
        fpath = target_dir / (name + ext)
        # Pad to realistic file size (50KB - 500KB)
        size = random.randint(50_000, 500_000)
        padding = content * (size // max(len(content), 1) + 1)
        fpath.write_bytes(padding[:size])
        created_files.append(fpath)
        log("  📄", DIM, f"Created: {name}{ext} ({size//1024}KB)")

    print()
    time.sleep(0.8)

    # ── PHASE 3: Touch canary file (trigger honeyfile detection) ─────────────
    if mode == 'slow':
        log("🪤", RED, "Phase 3: Scanning for valuable files... touching canary file...")
        try:
            _ = canary_path.read_bytes()  # Simulate ransomware opening the file
        except Exception:
            pass
        log("🔥", RED, f"CANARY ACCESSED: {canary_path.name} — ChainTrap should fire NOW")
        time.sleep(1.5)
    else:
        log("⚡", RED, "Phase 3: Fast mode — skipping recon, direct encryption...")
        time.sleep(0.3)

    # ── PHASE 4: ENCRYPT FILES ───────────────────────────────────────────────
    print()
    log("🔐", RED, f"Phase 4: ENCRYPTING {len(created_files)} files...")
    print()

    encrypted_files = []
    for i, fpath in enumerate(created_files):
        time.sleep(delay + random.uniform(-0.1, 0.3))

        try:
            original_data = fpath.read_bytes()
            encrypted_data = encrypt_bytes(original_data)

            # Write encrypted content over the original file
            # This is what ChainTrap detects — entropy spike on file write
            fpath.write_bytes(encrypted_data)

            # Rename to .locked (triggers rename-burst detector)
            locked_path = fpath.with_suffix('.locked')
            fpath.rename(locked_path)
            encrypted_files.append(locked_path)

            log("🔴", RED,
                f"[{i+1}/{len(created_files)}] ENCRYPTED: {fpath.name} "
                f"→ {locked_path.name}")
            log("   entropy:", AMBER, f"~7.9 bits/byte (was ~3.1)")

        except Exception as e:
            log("⚠", AMBER, f"Skipped {fpath.name}: {e}")

    # ── PHASE 5: Drop ransom note ─────────────────────────────────────────────
    print()
    time.sleep(0.5)
    ransom_note = target_dir / "!!! READ_ME_NOW.txt"
    ransom_note.write_text(
        "YOUR FILES HAVE BEEN ENCRYPTED\n"
        "================================\n\n"
        f"We have encrypted {len(encrypted_files)} files on this system.\n"
        "To recover your files, pay 2 BTC to wallet: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n\n"
        "You have 72 hours. After that, files will be permanently deleted.\n\n"
        "Do NOT contact law enforcement. Do NOT attempt to decrypt.\n\n"
        "-- LockBit 3.0\n"
    )
    log("📋", RED, "Ransom note dropped: !!! READ_ME_NOW.txt")

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    print()
    print(f"{RED}{'═'*60}{RESET}")
    print(f"{RED}{BOLD}  ATTACK COMPLETE{RESET}")
    print(f"{RED}{'═'*60}{RESET}")
    print(f"  Files encrypted : {RED}{len(encrypted_files)}{RESET}")
    print(f"  Canary touched  : {AMBER}{'Yes' if mode=='slow' else 'No (fast mode)'}{RESET}")
    print(f"  Ransom note     : {RED}Dropped{RESET}")
    print()
    print(f"  {GREEN}▶ ChainTrap should have detected this.{RESET}")
    print(f"  {GREEN}▶ Check the dashboard: http://localhost:5000{RESET}")
    print(f"  {GREEN}▶ Run: python main.py --chain   (to see blockchain){RESET}")
    print(f"  {GREEN}▶ Run: python main.py --events 20  (to see event log){RESET}")
    print()
    print(f"  {DIM}To clean up encrypted files:{RESET}")
    print(f"  {CYAN}python demo_ransomware.py --reset --target {target_dir}{RESET}\n")

    return encrypted_files

# ═══════════════════════════════════════════════════════════════════════════════
# RESET
# ═══════════════════════════════════════════════════════════════════════════════

def reset_demo(target_dir: Path):
    """Remove all .locked files and ransom notes from last demo."""
    print(f"\n{CYAN}Cleaning up demo files in {target_dir}...{RESET}\n")
    removed = 0
    for pattern in ["*.locked", "!!! READ_ME_NOW.txt", "~aaa_*", "~passwords_*", "~admin_*",
                    "AIIMS_*", "NIC_*", "MoH_*", "Server_Access_*", "CERT-In_*",
                    "Government_Tender_*", "PM_Office_*"]:
        for f in target_dir.glob(pattern):
            f.unlink(missing_ok=True)
            log("🗑", DIM, f"Removed: {f.name}")
            removed += 1
    print(f"\n{GREEN}  ✓ Cleaned {removed} files.{RESET}\n")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ChainTrap Demo — Ransomware Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo_ransomware.py --mode fast       # LockBit-style fast attack
  python demo_ransomware.py --mode slow       # Evasion-style slow attack
  python demo_ransomware.py --reset           # Clean up demo files
        """
    )
    parser.add_argument("--mode", choices=["fast", "slow"], default="fast",
                        help="Attack mode: fast (LockBit-style) or slow (evasion)")
    parser.add_argument("--target", type=str, default=None,
                        help="Target directory (default: ~/Desktop/ChainTrap_Demo_Folder)")
    parser.add_argument("--reset", action="store_true",
                        help="Clean up all demo files from last run")
    args = parser.parse_args()

    # Determine target directory
    if args.target:
        target = Path(args.target)
    else:
        # Default: use Desktop or temp dir
        desktop = Path.home() / "Desktop"
        if desktop.exists():
            target = desktop / "ChainTrap_Demo_Folder"
        else:
            target = Path.home() / "ChainTrap_Demo_Folder"

    banner()

    if args.reset:
        reset_demo(target)
        return

    # Safety check — don't run against system dirs
    dangerous = [Path.home(), Path("/"), Path("/tmp"), Path("C:\\"), Path("C:\\Windows")]
    if target in dangerous:
        print(f"{RED}Error: Refusing to run against {target} — too dangerous.{RESET}")
        sys.exit(1)

    print(f"  {AMBER}⚠  This script will create and encrypt files in:{RESET}")
    print(f"  {WHITE}{target}{RESET}")
    print(f"\n  {DIM}These are FAKE files created by the simulator.{RESET}")
    print(f"  {DIM}Your existing files are NOT affected.{RESET}\n")

    confirm = input(f"  {CYAN}Press ENTER to start the attack demo, or Ctrl+C to cancel: {RESET}")

    run_attack(target, args.mode)


if __name__ == "__main__":
    main()