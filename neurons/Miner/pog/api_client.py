from pathlib import Path
import time
import json
import base64

from .config import ATTESTATION_LAYER_URL, AUTH_TOKEN, CONNECT_TO, READ_TO
from .util import sign_hotkey_payload
from .logging import log


def post_json(path: str, payload: dict, headers_extra: dict | None = None):
    try:
        import requests

        headers = {"Content-Type": "application/json"}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        if headers_extra:
            headers.update(headers_extra)
        url = f"{ATTESTATION_LAYER_URL}{path}"
        r = requests.post(url, json=payload, headers=headers, timeout=(CONNECT_TO, READ_TO))
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log("api_post_failed", level="warn", path=path, err=str(e))
        return None


def post_file(path: str, fields: dict, file_path: Path, headers_extra: dict | None = None):
    try:
        import requests

        headers = {}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        if headers_extra:
            headers.update(headers_extra)
        url = f"{ATTESTATION_LAYER_URL}{path}"
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            r = requests.post(url, data=fields, files=files, headers=headers, timeout=(CONNECT_TO, READ_TO))
            r.raise_for_status()
            return r.json()
    except Exception as e:
        log("api_post_file_failed", level="warn", path=path, file=file_path.name, err=str(e))
        return None


def post_attestation(payload: dict):
    return post_json("/inst/attestation", payload)


def get_alloc_state(hotkey: str, wallet=None):
    alloc_state = None
    try:
        import requests

        headers = {}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        payload = {
            "purpose": "alloc_status_v1",
            "hotkey": hotkey,
            "ts": int(time.time()),
        }
        sig = sign_hotkey_payload(payload, wallet) if wallet else None
        if sig:
            sig_obj = {
                "hotkey": hotkey,
                "sig": sig,
                "ts": payload["ts"],
                "purpose": payload["purpose"],
            }
            sig_b64 = base64.b64encode(json.dumps(sig_obj, separators=(",", ":")).encode("utf-8")).decode("utf-8")
            # API expects Authorization: Signature <base64>
            headers["Authorization"] = f"Signature {sig_b64}"
        url = f"{ATTESTATION_LAYER_URL}/allocations-status/{hotkey}"
        r = requests.get(url, headers=headers, timeout=(CONNECT_TO, READ_TO))
        if r.status_code == 200:
            data = r.json()
            alloc_state = data.get("alloc_state")
    except Exception as e:
        log("alloc_status_failed", level="warn", err=str(e))
    return alloc_state


def send_heartbeat(inst_uuid, pk_M, coldkey, hw_static, hw_live, axon_ip, axon_port, ssh_port, hotkey_payload, hotkey_signature, sig_coldkey=None):
    payload = {
        "inst_uuid": inst_uuid,
        "pk_M": pk_M,
        "axon_ip": axon_ip,
        "axon_port": axon_port,
        "ssh_port": ssh_port,
    }
    if coldkey is not None:
        payload["coldkey"] = coldkey
    if sig_coldkey is not None:
        payload["sig_coldkey"] = sig_coldkey
    if hw_static is not None:
        payload["hw_static"] = hw_static
    if hw_live is not None:
        payload["hw_live"] = hw_live
    if hotkey_payload is not None:
        payload["hotkey_payload"] = hotkey_payload
    if hotkey_signature is not None:
        payload["hotkey_signature"] = hotkey_signature
    post_json("/inst/heartbeat", payload)


def get_metagraph_entry(hotkey: str, scope: str = "all", wallet=None) -> dict | None:
    """
    Query attestation layer /metagraph endpoint and return the entry for this hotkey.

    Args:
        hotkey: SS58 address to look up
        scope: Metagraph scope (default "all")
        wallet: Optional wallet for signing (if auth required)

    Returns:
        Entry dict if hotkey found, None otherwise.
        Entry format: {hotkey, coldkey, source, metagraph_uid, status, ...}
    """
    try:
        import requests

        headers = {}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"

        # Optional signature-based auth if wallet provided
        if wallet:
            payload = {
                "purpose": "metagraph_check_v1",
                "hotkey": hotkey,
                "ts": int(time.time()),
            }
            sig = sign_hotkey_payload(payload, wallet)
            if sig:
                sig_obj = {
                    "hotkey": hotkey,
                    "sig": sig,
                    "ts": payload["ts"],
                    "purpose": payload["purpose"],
                }
                sig_b64 = base64.b64encode(
                    json.dumps(sig_obj, separators=(",", ":")).encode("utf-8")
                ).decode("utf-8")
                headers["Authorization"] = f"Signature {sig_b64}"

        url = f"{ATTESTATION_LAYER_URL}/metagraph"
        params = {"scope": scope}
        r = requests.get(url, params=params, headers=headers, timeout=(CONNECT_TO, READ_TO))

        if r.status_code != 200:
            log("metagraph_fetch_failed", level="warn", status=r.status_code)
            return None

        data = r.json()
        entries = data.get("entries", [])

        # Find entry matching this hotkey
        for entry in entries:
            if entry.get("hotkey") == hotkey:
                return entry

        return None

    except Exception as e:
        log("metagraph_check_failed", level="warn", err=str(e))
        return None
