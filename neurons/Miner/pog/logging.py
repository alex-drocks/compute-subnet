import json
import os
import sys
from contextvars import ContextVar
from typing import Any, Dict, Optional

# Use bittensor logging for consistent formatting with the rest of the miner
try:
    import bittensor as bt
    _USE_BT_LOGGING = True
except ImportError:
    _USE_BT_LOGGING = False
    import logging
    _LOGGER = logging.getLogger("miner")

_CONFIGURED = False
_RUN_CTX: ContextVar[Dict[str, Optional[str]]] = ContextVar(
    "run_context", default={"inst_uuid": None, "pk_M": None, "run_id": None}
)

# Fields to exclude from log messages (too verbose)
_EXCLUDED_FIELDS = {"inst_uuid", "pk_M", "beacon_meta"}


def _bool_from_env(val: Optional[str], default: bool) -> bool:
    if val is None:
        return default
    return val.strip().lower() not in {"0", "false", "no"}


def _json_default(obj: Any) -> Any:
    try:
        return str(obj)
    except Exception:
        return "<unserializable>"


def configure_logging(level: Optional[str] = None, json_output: Optional[bool] = None):
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True


def set_run_context(inst_uuid: Optional[str], pk_M: Optional[str], run_id: Optional[str]):
    _RUN_CTX.set({"inst_uuid": inst_uuid, "pk_M": pk_M, "run_id": run_id})


def clear_run_context():
    _RUN_CTX.set({"inst_uuid": None, "pk_M": None, "run_id": None})


def _format_fields(**fields) -> str:
    """Format fields into a compact string, excluding verbose fields."""
    parts = []
    for k, v in fields.items():
        if k in _EXCLUDED_FIELDS:
            continue
        if isinstance(v, float):
            parts.append(f"{k}={v:.3f}")
        elif isinstance(v, (dict, list, tuple)):
            continue  # Skip complex objects
        else:
            parts.append(f"{k}={v}")
    return " | ".join(parts) if parts else ""


def log(event: str, level: str = "info", **fields):
    configure_logging()

    # Build message: "PoG: event_name | field1=val1 | field2=val2"
    field_str = _format_fields(**fields)
    if field_str:
        msg = f"PoG: {event} | {field_str}"
    else:
        msg = f"PoG: {event}"

    if _USE_BT_LOGGING:
        if level == "debug":
            bt.logging.debug(msg)
        elif level == "info":
            bt.logging.info(msg)
        elif level == "success":
            bt.logging.success(msg)
        elif level in ("warn", "warning"):
            bt.logging.warning(msg)
        elif level in ("error", "fatal", "critical"):
            bt.logging.error(msg)
        else:
            bt.logging.info(msg)
    else:
        # Fallback to print if bittensor not available
        print(f"[{level.upper()}] {msg}", file=sys.stdout, flush=True)
