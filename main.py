#!/usr/bin/env python3
"""
ChainTrap v2 — main.py

Production Entry Point.

Usage:
  python main.py              # Start monitoring with default config
  python main.py --verify     # Verify blockchain integrity only
  python main.py --chain      # Print chain summary
  python main.py --config     # Write default config template and exit
  python main.py --test       # Run self-test (simulate high-entropy write)

This file is the REAL entry point — NOT a simulation.
All output comes from live system activity.

Cross-platform: macOS, Windows, Linux.
"""

import sys
import os
import argparse
import logging
import json
import time
import hashlib
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))


def _print_banner() -> None:
    print("""
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║   ██████╗██╗  ██╗ █████╗ ██╗███╗  ██╗████████╗██████╗  █████╗ ██████╗   ║
║  ██╔════╝██║  ██║██╔══██╗██║████╗ ██║╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗  ║
║  ██║     ███████║███████║██║██╔██╗██║   ██║   ██████╔╝███████║██████╔╝  ║
║  ██║     ██╔══██║██╔══██║██║██║╚████║   ██║   ██╔══██╗██╔══██║██║       ║
║  ╚██████╗██║  ██║██║  ██║██║██║ ╚███║   ██║   ██║  ██║██║  ██║██║       ║
║   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝       ║
║                                                                         ║
║   Ransomware Detection & Protection System  v2.0                        ║
║   Patent-Ready | Cross-Platform | Blockchain-Anchored                   ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
""")


def cmd_monitor() -> None:
    """Start the full monitoring engine."""
    from core.monitor import ChainTrapMonitor
    monitor = ChainTrapMonitor()
    monitor.start()


def cmd_verify() -> None:
    """Verify blockchain integrity and print results."""
    from core.blockchain_logger import verify_chain, get_chain_summary, print_chain

    print("\n[ChainTrap] Verifying local blockchain integrity...\n")
    result = verify_chain()

    if result["ok"]:
        print(f"  ✅ Chain integrity: VALID")
    else:
        print(f"  ❌ Chain integrity: TAMPERED OR CORRUPTED")
        for err in result["errors"]:
            print(f"     → {err}")

    print(f"  Blocks verified: {result['blocks_verified']}")
    summary = get_chain_summary()
    print(f"  Node ID:         {summary['node_id']}")
    print(f"  Genesis:         {summary['genesis_timestamp']}")
    print(f"  Latest:          {summary['latest_timestamp']}")
    print(f"  Ransomware events logged: {summary['ransomware_events']}")
    print(f"  Head hash:       {summary['chain_head_hash']}")
    print()


def cmd_chain() -> None:
    """Print the last 20 blockchain blocks."""
    from core.blockchain_logger import print_chain
    print_chain(last_n=20)


def cmd_write_config() -> None:
    """Write default config template."""
    from config import write_default_config, CONFIG_FILE
    write_default_config()
    print(f"\n[ChainTrap] Config template written: {CONFIG_FILE}")
    print("Edit it to customize thresholds, directories, and alerts.\n")


def cmd_self_test() -> None:
    """
    Self-test: simulate a high-entropy file write in the decoy directory
    and verify ChainTrap would detect it.

    This is NOT a simulation — it actually writes a high-entropy file
    and runs the real analysis pipeline on it.
    """
    print("\n[ChainTrap Self-Test] Running detection pipeline...\n")

    # 1. Write a high-entropy (random) file
    import tempfile
    import secrets
    from core.entropy_analyzer import analyze_file, analyze_delta
    from core.blockchain_logger import add_event, verify_chain

    test_dir  = Path(tempfile.mkdtemp(prefix="chaintrap_test_"))
    test_file = test_dir / "test_document.docx"

    print(f"  Test directory: {test_dir}")

    # Write low-entropy file first (baseline)
    baseline_content = b"This is a normal document. " * 4000
    test_file.write_bytes(baseline_content)
    print(f"  [1] Baseline file written ({len(baseline_content):,} bytes)")

    baseline_result = analyze_file(str(test_file))
    print(f"      Entropy: {baseline_result.shannon_global:.4f}")
    print(f"      Magic valid: {baseline_result.magic_valid}")
    print(f"      Suspicious: {baseline_result.is_suspicious}")

    # Now simulate ransomware: overwrite with random bytes
    print("\n  [2] Simulating ransomware encryption (random bytes)...")
    encrypted_content = secrets.token_bytes(len(baseline_content))
    test_file.write_bytes(encrypted_content)
    print(f"      High-entropy content written ({len(encrypted_content):,} bytes)")

    encrypted_result = analyze_file(str(test_file))
    print(f"      Entropy:      {encrypted_result.shannon_global:.4f}")
    print(f"      Max window:   {encrypted_result.shannon_max_window:.4f}")
    print(f"      Chi p-value:  {encrypted_result.chi_p_value:.6f}")
    print(f"      Magic valid:  {encrypted_result.magic_valid}  (expected: False — random bytes ≠ OOXML)")
    print(f"      Suspicious:   {encrypted_result.is_suspicious}")
    print(f"      Signals:      {encrypted_result.signals_triggered}")
    print(f"      Score:        {encrypted_result.suspicion_score:.4f}")

    # Entropy delta
    delta_sus, delta_val, delta_desc = analyze_delta(
        baseline_result, encrypted_result, delta_threshold=1.5
    )
    print(f"\n  [3] Entropy delta analysis:")
    print(f"      Delta: {delta_val:.4f}")
    print(f"      Threshold breached: {delta_sus}")
    print(f"      Description: {delta_desc}")

    # Record to blockchain
    print("\n  [4] Recording to blockchain...")
    block = add_event({
        "event_type":  "SELF_TEST",
        "file_path":   str(test_file),
        "entropy":     encrypted_result.shannon_global,
        "delta":       delta_val,
        "signals":     encrypted_result.signals_triggered,
        "score":       encrypted_result.suspicion_score,
    })
    print(f"      Block #{block['index']} added. Hash: {block['hash'][:16]}...")

    # Verify chain
    vr = verify_chain()
    print(f"      Chain integrity: {'✅ VALID' if vr['ok'] else '❌ INVALID'}")

    # Final verdict
    detection = encrypted_result.is_suspicious or delta_sus
    print(f"\n  {'✅ DETECTION SUCCESSFUL' if detection else '❌ DETECTION MISSED'}")
    print(f"  Expected: True  |  Got: {detection}\n")

    # Cleanup
    try:
        import shutil
        shutil.rmtree(test_dir)
    except Exception:
        pass

    if not detection:
        print("  ⚠️  Self-test failed. Review thresholds in chaintrap.json.\n")
        sys.exit(1)
    else:
        print("  Self-test passed. ChainTrap is functioning correctly.\n")


def cmd_events(last_n: int = 20) -> None:
    """Print the last N events from the event log."""
    from core.event_logger import read_events

    events = read_events(last_n=last_n)
    if not events:
        print("[ChainTrap] No events logged yet.")
        return

    print(f"\n[ChainTrap] Last {len(events)} events:\n")
    for ev in events:
        ts   = ev.get("timestamp", "?")
        etype = ev.get("event_type", "?")
        sev   = ev.get("severity", "")
        fp    = ev.get("file_path", "")
        print(f"  [{ts}] {etype} {f'[{sev}]' if sev else ''} {fp}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="chaintrap",
        description="ChainTrap v2 — Ransomware Detection & Protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py               # Start monitoring (default)
  python main.py --verify      # Check blockchain integrity
  python main.py --chain       # Print last 20 blockchain blocks
  python main.py --config      # Write default config file
  python main.py --test        # Run self-test
  python main.py --events 50   # Show last 50 events
        """
    )
    parser.add_argument("--verify",  action="store_true",  help="Verify blockchain integrity")
    parser.add_argument("--chain",   action="store_true",  help="Print blockchain")
    parser.add_argument("--config",  action="store_true",  help="Write default config template")
    parser.add_argument("--test",    action="store_true",  help="Run self-test")
    parser.add_argument("--events",  type=int, nargs="?",  const=20, default=None,
                        help="Show last N events (default 20)")
    parser.add_argument("--verbose", action="store_true",  help="Enable DEBUG logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    _print_banner()

    if args.verify:
        cmd_verify()
    elif args.chain:
        cmd_chain()
    elif args.config:
        cmd_write_config()
    elif args.test:
        cmd_self_test()
    elif args.events is not None:
        cmd_events(last_n=args.events)
    else:
        cmd_monitor()


if __name__ == "__main__":
    main()
