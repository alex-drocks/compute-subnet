from typing import Optional
import hashlib
import json
import base64
import time

from .logging import log


def make_pseudo_sig(label: str, value: Optional[str]) -> Optional[str]:
    """
    Temporary stand-in for a real bittensor signature.

    Returns a 128-hex-char string (~64 bytes) or None if value is empty.
    """
    if not value:
        return None
    msg = f"{label}:{value}".encode("utf-8")
    h1 = hashlib.sha256(msg).hexdigest()
    h2 = hashlib.sha256(b"salt:" + msg).hexdigest()
    return h1 + h2  # 64 hex + 64 hex = 128 hex


def hotkey_to_pubkey_bytes(pk_M: str) -> bytes:
    """
    Convert a hotkey string (preferably ss58) to raw public key bytes.
    """
    s = (pk_M or "").strip()
    if not s:
        raise ValueError("empty hotkey")
    try:
        import bittensor as bt

        kp = bt.Keypair(ss58_address=s)
        return kp.public_key
    except Exception:
        raise ValueError("invalid hotkey format (expected ss58)")


def sign_hotkey_payload(payload: dict, wallet=None) -> Optional[str]:
    """
    Sign canonical JSON payload with the miner hotkey.
    Returns hex signature or None on failure (miner continues without a sig).
    """
    try:
        if wallet is None:
            return None
        w = wallet
        try:
            w.unlock_hotkey()
        except Exception:
            # best-effort; hotkey may already be unlocked or unencrypted
            pass
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload_json.encode("utf-8")).digest()
        sig = w.hotkey.sign(digest)
        return sig.hex()
    except Exception as e:
        log("hotkey_sign_failed", level="warn", err=str(e))
        return None


def build_signature_header(purpose: str, body: dict, wallet=None, hotkey: Optional[str] = None) -> dict:
    """
    Build Authorization: Signature header for a given payload+purpose.
    """
    if wallet is None or not hotkey:
        return {}
    try:
        payload = {"purpose": purpose, "body": body, "ts": int(time.time())}
        sig = sign_hotkey_payload(payload, wallet)
        if not sig:
            return {}
        sig_obj = {"hotkey": hotkey, "sig": sig, "ts": payload["ts"], "purpose": purpose}
        sig_b64 = base64.b64encode(json.dumps(sig_obj, separators=(",", ":")).encode("utf-8")).decode("utf-8")
        return {"Authorization": f"Signature {sig_b64}"}
    except Exception as e:
        log("signature_build_failed", level="warn", err=str(e))
        return {}
