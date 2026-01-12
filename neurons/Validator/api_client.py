import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import requests
import yaml

import bittensor as bt


def _canonical_json(payload: dict) -> bytes:
    """
    Canonical JSON encoding (sorted keys, no spaces) for signing.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_api_cfg() -> dict:
    """
    Load Attestation Layer config from env with config.yaml fallback.
    """
    cfg = {}
    try:
        data = yaml.safe_load(open("config.yaml", "r"))
        if isinstance(data, dict):
            cfg = data.get("attestation_layer", {}) or {}
    except Exception:
        cfg = {}
    return cfg


def _api_base() -> str:
    cfg = _load_api_cfg()
    base = os.getenv("ATTESTATION_LAYER_URL") or cfg.get("url")
    if base:
        return base.rstrip("/")

    host = os.getenv("ATTESTATION_LAYER_HOST") or cfg.get("host", "127.0.0.1")
    port = os.getenv("ATTESTATION_LAYER_PORT") or cfg.get("port", 8080)
    try:
        port = int(port)
    except Exception:
        port = 8080
    base_path = os.getenv("ATTESTATION_LAYER_BASE_PATH") or cfg.get("base_path", "/v1") or "/v1"
    base_path = base_path if str(base_path).startswith("/") else f"/{base_path}"
    return f"http://{host}:{port}{base_path}".rstrip("/")


def _api_auth_token() -> Optional[str]:
    cfg = _load_api_cfg()
    return (
        os.getenv("ATTESTATION_LAYER_AUTH_TOKEN")
        or cfg.get("auth_token")
    )


def _timeouts() -> tuple[float, float]:
    cfg = _load_api_cfg()
    connect = os.getenv("ATTESTATION_LAYER_CONNECT_TIMEOUT") or cfg.get("connect_timeout_sec", 5)
    read = os.getenv("ATTESTATION_LAYER_READ_TIMEOUT") or cfg.get("read_timeout_sec", 30)
    try:
        connect_f = float(connect)
    except Exception:
        connect_f = 5.0
    try:
        read_f = float(read)
    except Exception:
        read_f = 30.0
    return connect_f, read_f


def _retry_settings() -> tuple[int, float, float, set[int]]:
    cfg = _load_api_cfg()
    retry_max = os.getenv("ATTESTATION_LAYER_RETRY_MAX") or cfg.get("retry_max", 2)
    backoff_base = os.getenv("ATTESTATION_LAYER_RETRY_BASE_SEC") or cfg.get("retry_base_sec", 0.5)
    backoff_max = os.getenv("ATTESTATION_LAYER_RETRY_MAX_SEC") or cfg.get("retry_max_sec", 5.0)
    statuses = os.getenv("ATTESTATION_LAYER_RETRY_STATUSES") or cfg.get(
        "retry_statuses",
        "408,429,500,502,503,504",
    )
    try:
        retry_max_i = int(retry_max)
    except Exception:
        retry_max_i = 2
    try:
        backoff_base_f = float(backoff_base)
    except Exception:
        backoff_base_f = 0.5
    try:
        backoff_max_f = float(backoff_max)
    except Exception:
        backoff_max_f = 5.0
    try:
        status_set = {int(s.strip()) for s in str(statuses).split(",") if s.strip()}
    except Exception:
        status_set = {408, 429, 500, 502, 503, 504}
    return retry_max_i, backoff_base_f, backoff_max_f, status_set


def _cache_ttl_seconds() -> float:
    cfg = _load_api_cfg()
    ttl = os.getenv("ATTESTATION_LAYER_CACHE_TTL") or cfg.get("cache_ttl_sec", 300)
    try:
        return float(ttl)
    except Exception:
        return 300.0


def _build_signature_header(purpose: str, payload_body: Optional[dict], wallet: Optional[bt.wallet]) -> Dict[str, str]:
    """
    Build Authorization: Signature header using the validator hotkey.
    """
    if wallet is None:
        return {}

    ts = int(time.time())
    payload = {"purpose": purpose, "ts": ts}
    if payload_body:
        payload.update(payload_body)

    try:
        try:
            wallet.unlock_hotkey()
        except Exception:
            pass
        digest = hashlib.sha256(_canonical_json(payload)).digest()
        sig = wallet.hotkey.sign(digest).hex()
        hotkey = getattr(wallet.hotkey, "ss58_address", None) or str(wallet.hotkey)
        sig_obj = {"hotkey": hotkey, "sig": sig, "ts": ts, "purpose": purpose}
        sig_b64 = base64.b64encode(
            json.dumps(sig_obj, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")
        return {"Authorization": f"Signature {sig_b64}"}
    except Exception as e:
        bt.logging.warning(f"[vali-api] failed to sign request: {e}")
        return {}


@dataclass
class ApiInstance:
    inst_uuid: str
    pk_M: str
    current_status: str
    hardware: Dict[str, Any]
    stats: Dict[str, Any]

    @property
    def primary_gpu_uuid(self) -> Optional[str]:
        if not isinstance(self.hardware, dict):
            return None
        # First check direct field from API
        if self.hardware.get("primary_gpu_uuid"):
            return self.hardware["primary_gpu_uuid"]
        # Fallback to gpus array
        gpus = self.hardware.get("gpus")
        if isinstance(gpus, list) and gpus:
            try:
                return gpus[0].get("uuid")
            except Exception:
                return None
        return None

    @property
    def primary_gpu_name(self) -> Optional[str]:
        if not isinstance(self.hardware, dict):
            return None
        # First check direct field from API
        if self.hardware.get("primary_gpu_name"):
            return self.hardware["primary_gpu_name"]
        # Fallback to gpus array
        gpus = self.hardware.get("gpus")
        if isinstance(gpus, list) and gpus:
            try:
                return gpus[0].get("name")
            except Exception:
                return None
        return None

    @property
    def gpu_count(self) -> int:
        if not isinstance(self.hardware, dict):
            return 0
        # First check direct field from API
        if self.hardware.get("gpu_count") is not None:
            try:
                return int(self.hardware["gpu_count"])
            except (ValueError, TypeError):
                pass
        # Fallback to gpus array length
        gpus = self.hardware.get("gpus")
        return len(gpus) if isinstance(gpus, list) else 0


class ValidationApiClient:
    """
    Thin client for the validation API stats endpoints.
    """

    def __init__(self, wallet: Optional[bt.wallet] = None):
        self.wallet = wallet
        self.base = _api_base()
        self.auth_token = _api_auth_token()
        self.connect_timeout, self.read_timeout = _timeouts()
        self.retry_max, self.backoff_base, self.backoff_max, self.retry_statuses = _retry_settings()
        self.cache_ttl_sec = _cache_ttl_seconds()
        self._cache: dict[str, tuple[float, dict]] = {}

    def _build_headers(
        self,
        purpose: str,
        payload_body: Optional[dict],
        wallet_override: Optional[bt.wallet] = None,
    ) -> Dict[str, str]:
        wallet = wallet_override or self.wallet
        if wallet is not None:
            return _build_signature_header(purpose, payload_body, wallet)
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[dict]:
        url = f"{self.base}{path}"
        if headers is None:
            headers = self._build_headers("stats_full", None)
        try:
            attempt = 0
            while True:
                try:
                    r = requests.get(
                        url,
                        params=params or {},
                        headers=headers,
                        timeout=(self.connect_timeout, self.read_timeout),
                    )
                except Exception as e:
                    if attempt >= self.retry_max:
                        raise e
                    attempt += 1
                    delay = min(self.backoff_max, self.backoff_base * (2 ** (attempt - 1)))
                    time.sleep(delay)
                    continue

                if r.status_code in self.retry_statuses:
                    if attempt >= self.retry_max:
                        bt.logging.warning(f"[vali-api] GET {url} failed: HTTP {r.status_code}")
                        return None
                    attempt += 1
                    delay = min(self.backoff_max, self.backoff_base * (2 ** (attempt - 1)))
                    time.sleep(delay)
                    continue

                if r.status_code >= 400:
                    bt.logging.warning(f"[vali-api] GET {url} failed: HTTP {r.status_code}")
                    return None

                return r.json()
        except Exception as e:
            bt.logging.warning(f"[vali-api] GET {url} failed: {e}")
            return None

    def _post(
        self,
        path: str,
        body: dict,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[dict]:
        """POST with retry logic, mirroring _get pattern."""
        url = f"{self.base}{path}"
        if headers is None:
            headers = {}
        headers["Content-Type"] = "application/json"
        try:
            attempt = 0
            while True:
                try:
                    r = requests.post(
                        url,
                        json=body,
                        headers=headers,
                        timeout=(self.connect_timeout, self.read_timeout),
                    )
                except Exception as e:
                    if attempt >= self.retry_max:
                        raise e
                    attempt += 1
                    delay = min(self.backoff_max, self.backoff_base * (2 ** (attempt - 1)))
                    time.sleep(delay)
                    continue

                if r.status_code in self.retry_statuses:
                    if attempt >= self.retry_max:
                        bt.logging.warning(f"[vali-api] POST {url} failed: HTTP {r.status_code}")
                        return None
                    attempt += 1
                    delay = min(self.backoff_max, self.backoff_base * (2 ** (attempt - 1)))
                    time.sleep(delay)
                    continue

                if r.status_code >= 400:
                    bt.logging.warning(f"[vali-api] POST {url} failed: HTTP {r.status_code}")
                    return None

                return r.json()
        except Exception as e:
            bt.logging.warning(f"[vali-api] POST {url} failed: {e}")
            return None

    def _cache_get(self, key: str) -> Optional[dict]:
        entry = self._cache.get(key)
        if not entry:
            return None
        ts, data = entry
        if (time.time() - ts) <= self.cache_ttl_sec:
            return data
        return None

    def _cache_set(self, key: str, data: dict) -> None:
        self._cache[key] = (time.time(), data)

    def _get_with_cache(
        self,
        cache_key: str,
        path: str,
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]],
    ) -> tuple[Optional[dict], str]:
        data = self._get(path, params=params, headers=headers)
        if data is not None:
            self._cache_set(cache_key, data)
            return data, "live"

        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached, "cache"

        return None, "none"

    def fetch_instances_full(self, statuses: Optional[Iterable[str]] = None) -> List[ApiInstance]:
        instances, _source = self.fetch_instances_full_with_meta(statuses=statuses)
        return instances or []

    def fetch_instances_full_with_meta(
        self,
        statuses: Optional[Iterable[str]] = None,
    ) -> tuple[Optional[List[ApiInstance]], str]:
        """
        Fetch instances with hardware, optionally filtered by statuses.
        """
        params: Dict[str, Any] = {"scope": "all"}
        if statuses:
            params["status"] = ",".join(statuses)

        cache_key = f"instances_full:{params.get('status', 'all')}"
        data, source = self._get_with_cache(
            cache_key,
            "/stats/instances/full",
            params=params,
            headers=self._build_headers("stats_full", None),
        )
        if not data:
            return None, "none"

        insts_raw = data.get("instances") if isinstance(data, dict) else None
        if not isinstance(insts_raw, list):
            return None, source

        out: List[ApiInstance] = []
        for item in insts_raw:
            try:
                stats = item.get("stats", {}) if isinstance(item, dict) else {}
                hardware = item.get("hardware", {}) if isinstance(item, dict) else {}
                inst_uuid = stats.get("inst_uuid") or hardware.get("inst_uuid") or item.get("inst_uuid")
                pk_M = stats.get("pk_M") or item.get("pk_M")
                current_status = (stats.get("current_status") or "").lower()
                if not inst_uuid or not pk_M:
                    continue
                out.append(
                    ApiInstance(
                        inst_uuid=str(inst_uuid),
                        pk_M=str(pk_M),
                        current_status=current_status,
                        hardware=hardware,
                        stats=stats,
                    )
                )
            except Exception:
                continue
        return out, source

    def fetch_allocation_status(
        self,
        hotkey: str,
        wallet_override: Optional[bt.wallet] = None,
    ) -> Optional[dict]:
        payload = {"hotkey": hotkey}
        headers = self._build_headers("alloc_status_v1", payload, wallet_override=wallet_override)
        return self._get(f"/allocations-status/{hotkey}", headers=headers)

    def fetch_allocations_status(
        self,
        scope: str = "all",
        limit: int = 10000,
        wallet_override: Optional[bt.wallet] = None,
    ) -> Optional[dict]:
        params = {"scope": scope, "limit": max(1, min(int(limit), 10000))}
        headers = self._build_headers("alloc_status_all_v1", None, wallet_override=wallet_override)
        return self._get("/allocations-status", params=params, headers=headers)

    def fetch_allocations_status_with_meta(
        self,
        scope: str = "all",
        limit: int = 10000,
        wallet_override: Optional[bt.wallet] = None,
    ) -> tuple[Optional[dict], str]:
        params = {"scope": scope, "limit": max(1, min(int(limit), 10000))}
        headers = self._build_headers("alloc_status_all_v1", None, wallet_override=wallet_override)
        cache_key = f"allocations_status:{params['scope']}:{params['limit']}"
        return self._get_with_cache(cache_key, "/allocations-status", params=params, headers=headers)

    def sync_allocations(
        self,
        allocations: List[dict],
        wallet_override: Optional[bt.wallet] = None,
    ) -> Optional[dict]:
        """
        POST allocation status updates to the validation API.

        Args:
            allocations: List of allocation state changes, each with:
                - "key": miner hotkey (SS58 address)
                - "state": one of "allocated", "free", "banned", "unknown"
            wallet_override: Optional wallet to use for signing

        Returns:
            API response dict or None on failure

        API endpoint: POST /validator/allocations
        Body format:
        {
            "hotkey": "validator_ss58_address",
            "payload": {"allocations": [{"key": "miner_hotkey", "state": "allocated|free"}]},
            "signature": "hex_signature",
            "ts": timestamp,
            "purpose": "validator_alloc_v1"
        }
        """
        if not allocations:
            return {"status": "ok", "message": "No allocations to sync"}

        wallet = wallet_override or self.wallet
        if wallet is None:
            bt.logging.warning("[vali-api] Cannot sync allocations: no wallet available")
            return None

        ts = time.time()  # Must be float to match 3rd party signature format
        purpose = "validator_alloc_v1"

        try:
            try:
                wallet.unlock_hotkey()
            except Exception:
                pass

            hotkey_addr = getattr(wallet.hotkey, "ss58_address", None) or str(wallet.hotkey)

            # Build the inner payload
            inner_payload = {"allocations": allocations}

            # Build the payload to sign (matches 3rd party code format)
            sign_payload = {
                "purpose": purpose,
                "allocations": allocations,
                "ts": ts,
            }

            # Sign the canonical JSON
            digest = hashlib.sha256(_canonical_json(sign_payload)).digest()
            sig = wallet.hotkey.sign(digest).hex()

            # Build request body per API spec
            body = {
                "hotkey": hotkey_addr,
                "payload": inner_payload,
                "signature": sig,
                "ts": ts,
                "purpose": purpose,
            }

            return self._post("/validator/allocations", body)

        except Exception as e:
            bt.logging.warning(f"[vali-api] sync_allocations failed: {e}")
            return None

    def reload_config(self) -> bool:
        """
        Reload attestation layer configuration from config.yaml/env.
        Only updates non-empty values. Returns True if endpoint changed.
        """
        try:
            old_base = self.base
            new_base = _api_base()
            new_token = _api_auth_token()
            new_connect, new_read = _timeouts()
            new_retry_max, new_backoff_base, new_backoff_max, new_retry_statuses = _retry_settings()
            new_cache_ttl = _cache_ttl_seconds()

            # Only update if new values are valid/non-empty
            if new_base and new_base.strip():
                self.base = new_base
            if new_token is not None:
                self.auth_token = new_token
            if new_connect > 0:
                self.connect_timeout = new_connect
            if new_read > 0:
                self.read_timeout = new_read
            if new_retry_max >= 0:
                self.retry_max = new_retry_max
            if new_backoff_base > 0:
                self.backoff_base = new_backoff_base
            if new_backoff_max > 0:
                self.backoff_max = new_backoff_max
            if new_retry_statuses:
                self.retry_statuses = new_retry_statuses
            if new_cache_ttl > 0:
                self.cache_ttl_sec = new_cache_ttl

            changed = old_base != self.base
            if changed:
                self._cache.clear()
            return changed
        except Exception as e:
            bt.logging.warning(f"[vali-api] reload_config failed: {e}")
            return False
