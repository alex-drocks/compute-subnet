import time
from collections import OrderedDict
from typing import Optional, Tuple

from .config import (
    RPC_HTTP,
    RPC_WSS,
    RPC_TIMEOUT,
    HEAD_TTL_SEC,
    RPC_BACKOFF_SEC,
    BLOCK_HASH_CACHE_MAX,
)
from .logging import log


def _rpc_http(url: str, method: str, params: list):
    import json as _json
    import urllib.request

    req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
    payload = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(req, data=payload, timeout=RPC_TIMEOUT) as resp:
        obj = _json.loads(resp.read().decode())
        if "error" in obj:
            raise RuntimeError(str(obj["error"]))
        return obj["result"]


def _rpc_wss(url: str, method: str, params: list):
    from websocket import create_connection  # type: ignore
    import json as _json

    ws = create_connection(url, timeout=RPC_TIMEOUT)
    try:
        ws.send(_json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        obj = _json.loads(ws.recv())
        if "error" in obj:
            raise RuntimeError(str(obj["error"]))
        return obj["result"]
    finally:
        try:
            ws.close()
        except Exception:
            pass


def rpc_call(method: str, params: list):
    last_err = None
    if RPC_HTTP:
        try:
            return _rpc_http(RPC_HTTP, method, params)
        except Exception as e:
            last_err = e
    if RPC_WSS:
        try:
            return _rpc_wss(RPC_WSS, method, params)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"No working RPC endpoint for {method}. Last error: {last_err}")


def get_finalized_head() -> Tuple[str, int]:
    h = rpc_call("chain_getFinalizedHead", [])
    hdr = rpc_call("chain_getHeader", [h])
    return h, int(hdr["number"], 16)


def get_block_hash(num: int) -> str:
    return rpc_call("chain_getBlockHash", [num])


# ---------- RPC caching / backoff ----------
_HEAD_CACHE = {"hash": None, "number": None, "ts": 0.0}
_RPC_BACKOFF_UNTIL = 0.0
_BLOCK_HASH_CACHE: "OrderedDict[int, str]" = OrderedDict()


def get_finalized_number_cached() -> Optional[int]:
    """
    Cached finalized block number with TTL and RPC backoff.
    Returns last known finalized number (or None if unknown).
    """
    global _RPC_BACKOFF_UNTIL
    now = time.monotonic()

    # Respect backoff window
    if now < _RPC_BACKOFF_UNTIL:
        return _HEAD_CACHE["number"]

    # Use cached head if still fresh
    if (_HEAD_CACHE["number"] is not None) and (
        (now - _HEAD_CACHE["ts"]) <= HEAD_TTL_SEC
    ):
        return _HEAD_CACHE["number"]

    # Refresh from chain
    try:
        h, num = get_finalized_head()
    except Exception as e:
        _RPC_BACKOFF_UNTIL = now + RPC_BACKOFF_SEC
        log(
            "rpc_error",
            level="warn",
            where="cached_getFinalizedHead",
            err=str(e),
            backoff_sec=RPC_BACKOFF_SEC,
        )
        return _HEAD_CACHE["number"]

    # If hash unchanged, just refresh timestamp
    if h == _HEAD_CACHE["hash"] and _HEAD_CACHE["number"] is not None:
        _HEAD_CACHE["ts"] = now
        return _HEAD_CACHE["number"]

    _HEAD_CACHE["hash"] = h
    _HEAD_CACHE["number"] = num
    _HEAD_CACHE["ts"] = now
    return num


def get_block_hash_cached(num: int) -> str:
    """
    Cached block hash lookup with LRU eviction.
    """
    if num in _BLOCK_HASH_CACHE:
        _BLOCK_HASH_CACHE.move_to_end(num)
        return _BLOCK_HASH_CACHE[num]
    h = get_block_hash(num)
    _BLOCK_HASH_CACHE[num] = h
    if len(_BLOCK_HASH_CACHE) > BLOCK_HASH_CACHE_MAX:
        _BLOCK_HASH_CACHE.popitem(last=False)
    return h
