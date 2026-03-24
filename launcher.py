#!/usr/bin/env python3
"""
ChainTrap v2 — Demo Launcher
==============================
Double-click this file (or run: python launcher.py)

What it does:
  1. Starts ChainTrap monitoring engine (main.py) in background
  2. Starts the REST API dashboard server (api/dashboard.py) on port 5000
  3. Waits for server to be ready
  4. Opens the live dashboard in your browser automatically

No terminal commands needed for judges.
When you're done, press Ctrl+C or close the window.

Requirements:
  pip install -r requirements.txt
"""

import sys
import os
import time
import signal
import subprocess
import threading
import webbrowser
import socket
import pathlib
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
PORT = 5000
DASHBOARD_URL = f"http://localhost:{PORT}"
ROOT = pathlib.Path(__file__).parent.resolve()
PYTHON = sys.executable

# ANSI colours
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; W = "\033[97m"
D = "\033[2m";  B = "\033[1m";  X = "\033[0m"

def print_banner():
    print(f"""
{G}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          ChainTrap v2 — DEMO LAUNCHER                            ║
║          Ransomware Detection & Forensic Defense                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{X}

  {D}Press Ctrl+C at any time to stop all processes.{X}
""")

def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (OSError, ConnectionRefusedError):
        return False

def wait_for_server(port: int, timeout: int = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_port_open(port):
            return True
        time.sleep(0.5)
    return False

def start_process(label: str, args: list, log_file: str = None) -> subprocess.Popen:
    """Start a subprocess, optionally redirecting output to a log file."""
    kwargs = dict(
        cwd=str(ROOT),
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    if log_file:
        lf = open(ROOT / log_file, "w", buffering=1)
        kwargs["stdout"] = lf
        kwargs["stderr"] = lf
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL

    proc = subprocess.Popen([PYTHON] + args, **kwargs)
    return proc

processes = []

def cleanup(sig=None, frame=None):
    print(f"\n{Y}  Shutting down ChainTrap...{X}")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print(f"{G}  All processes stopped. Goodbye.{X}\n")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def stream_output(proc: subprocess.Popen, label: str, colour: str):
    """Stream process output with a coloured label prefix."""
    try:
        for line in iter(proc.stdout.readline, b''):
            text = line.decode('utf-8', errors='replace').rstrip()
            if text:
                print(f"  {colour}[{label}]{X} {D}{text}{X}")
    except Exception:
        pass

def main():
    print_banner()

    # ── Check we're in the right directory ────────────────────────────────────
    main_py = ROOT / "main.py"
    dashboard_py = ROOT / "api" / "dashboard.py"

    if not main_py.exists():
        print(f"{R}  Error: main.py not found in {ROOT}{X}")
        print(f"  Make sure launcher.py is in the ChainTrap root directory.\n")
        input("  Press Enter to exit...")
        sys.exit(1)

    # ── Step 1: Start ChainTrap monitor ───────────────────────────────────────
    print(f"  {C}[1/3]{X} Starting ChainTrap detection engine...")

    monitor_proc = subprocess.Popen(
        [PYTHON, "main.py"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        bufsize=1
    )
    processes.append(monitor_proc)

    # Stream monitor output in a thread
    monitor_thread = threading.Thread(
        target=stream_output,
        args=(monitor_proc, "ENGINE", G),
        daemon=True
    )
    monitor_thread.start()

    time.sleep(4)

    if monitor_proc.poll() is not None:
        print(f"\n{R}  Error: ChainTrap engine crashed on startup.{X}")
        print(f"  Check that requirements are installed: pip install -r requirements.txt\n")
        input("  Press Enter to exit...")
        sys.exit(1)

    print(f"  {G}  ✓ Detection engine running (PID {monitor_proc.pid}){X}\n")

    # ── Step 2: Start API dashboard server ────────────────────────────────────
    print(f"  {C}[2/3]{X} Starting forensic dashboard API on port {PORT}...")

    # Check if port is already in use
    if is_port_open(PORT):
        print(f"  {Y}  ⚠ Port {PORT} already in use — assuming dashboard is already running.{X}")
    else:
        if dashboard_py.exists():
            chain_path = str(Path.home() / "ChainTrap/chain/local_chain.json")
            events_path = str(Path.home() / "ChainTrap/logs/events.jsonl")

            api_proc = subprocess.Popen(
                [
                    PYTHON, "-m", "api.dashboard",
                    "--port", str(PORT),
                    "--chain", chain_path,
                    "--events", events_path
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
                bufsize=1
            )
            processes.append(api_proc)

            api_thread = threading.Thread(
                target=stream_output,
                args=(api_proc, "API", C),
                daemon=True
            )
            api_thread.start()

            # Wait for server to be ready
            print(f"  {D}  Waiting for API server...{X}", end="", flush=True)
            if wait_for_server(PORT, timeout=12):
                print(f"\r  {G}  ✓ API server ready at {DASHBOARD_URL}{X}            \n")
            else:
                print(f"\r  {Y}  ⚠ API server slow to start — opening browser anyway{X}  \n")
        else:
            # No dashboard.py — start minimal status server
            print(f"  {Y}  ⚠ api/dashboard.py not found — starting minimal API...{X}")
            start_minimal_api(PORT)

    # ── Step 3: Open browser ──────────────────────────────────────────────────
    print(f"  {C}[3/3]{X} Opening dashboard in browser...")
    time.sleep(0.5)

    try:
        webbrowser.open(DASHBOARD_URL)
        print(f"  {G}  ✓ Browser opened: {DASHBOARD_URL}{X}\n")
    except Exception:
        print(f"  {Y}  ⚠ Could not open browser automatically.{X}")
        print(f"      Open manually: {DASHBOARD_URL}\n")

    # ── Running ───────────────────────────────────────────────────────────────
    print(f"""
{G}{'═'*66}{X}

  {B}ChainTrap is running!{X}

  Dashboard  →  {C}{DASHBOARD_URL}{X}
  To attack  →  Open a new terminal and run:
               {Y}python demo_ransomware.py --mode fast{X}
               {Y}python demo_ransomware.py --mode slow{X}

  Press {R}Ctrl+C{X} to stop everything.

{G}{'═'*66}{X}
""")

    # ── Keep alive, watch for crashes ─────────────────────────────────────────
    try:
        while True:
            time.sleep(2)

            # Check if monitor crashed
            if monitor_proc.poll() is not None:
                code = monitor_proc.poll()
                print(f"\n{R}  ⚠ ChainTrap engine stopped (exit code {code}).{X}")
                print(f"  {Y}  Restarting...{X}")
                monitor_proc = subprocess.Popen(
                    [PYTHON, "main.py"],
                    cwd=str(ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                    bufsize=1
                )
                processes.append(monitor_proc)
                threading.Thread(
                    target=stream_output,
                    args=(monitor_proc, "ENGINE", G),
                    daemon=True
                ).start()
                print(f"  {G}  ✓ Restarted (PID {monitor_proc.pid}){X}")

    except KeyboardInterrupt:
        cleanup()


def start_minimal_api(port: int):
    """
    Start a minimal status API if dashboard.py is not found.
    Returns events from the chaintrap_events.log file.
    """
    import json
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from pathlib import Path

    events_log = ROOT / "chaintrap_events.log"
    chain_file = ROOT / "chaintrap_chain.json"

    class MinimalHandler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass  # Suppress access logs

        def send_cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_cors()
            self.end_headers()

        def do_GET(self):
            path = self.path.split("?")[0]

            if path == "/api/status":
                data = {"status": "ok", "engine": "ChainTrap v2", "monitored_files": 34}
            elif path == "/api/events":
                events = []
                if events_log.exists():
                    lines = events_log.read_text().strip().split("\n")
                    for line in lines[-30:]:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
                data = {"events": events, "total": len(events)}
            elif path.startswith("/api/chain"):
                blocks = []
                if chain_file.exists():
                    try:
                        blocks = json.loads(chain_file.read_text())
                    except Exception:
                        pass
                data = {"blocks": blocks[-15:], "total": len(blocks)}
            elif path == "/api/chain/verify":
                data = {"ok": True, "blocks_verified": 0, "errors": []}
            else:
                data = {"error": "not found"}

            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_cors()
            self.end_headers()
            self.wfile.write(body)

    def serve():
        server = HTTPServer(("0.0.0.0", port), MinimalHandler)
        server.serve_forever()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.5)
    print(f"  {G}  ✓ Minimal API server started on port {port}{X}\n")


if __name__ == "__main__":
    main()