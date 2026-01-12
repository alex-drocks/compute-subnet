import os
from pathlib import Path
from typing import Tuple, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()


def _env(key: str) -> str | None:
    val = os.getenv(key)
    if val is None:
        return None
    val = val.strip()
    return val if val else None


def _env_int(key: str, default: Optional[int]) -> Optional[int]:
    val = _env(key)
    if val is None:
        return default
    try:
        return int(val)
    except Exception:
        return default


def _env_float(key: str, default: Optional[float]) -> Optional[float]:
    val = _env(key)
    if val is None:
        return default
    try:
        return float(val)
    except Exception:
        return default

# -------- CUDA / Torch env (early) --------
os.environ.setdefault("CUDA_MODULE_LOADING", "EAGER")
os.environ.setdefault("CUDA_DISABLE_PTX_JIT", "1")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "max_split_size_mb:1024,expandable_segments:True")
for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
    os.environ.setdefault(v, "1")

# -------- load config --------
try:
    CFG = yaml.safe_load(Path("config.yaml").read_text()) or {}
except Exception:
    CFG = {}

# Config sections
MINER = CFG.get("miner", {})
CHAIN = CFG.get("chain", {})
POG = CFG.get("pog", {})

# Miner paths and identity
run_root_env = _env("RUN_ROOT_PATH")
RUN_ROOT = Path(run_root_env or MINER.get("run_root_path", "/dev/shm/miner"))
poll_sec_env = _env_float("MINER_POLL_SEC", None)
POLL_SEC = float(poll_sec_env if poll_sec_env is not None else MINER.get("poll_sec", 0.5))

# Chain settings
rpc_wss_env = _env("MINER_RPC_WSS")
rpc_http_env = _env("MINER_RPC_HTTP")
RPC_WSS = rpc_wss_env if rpc_wss_env is not None else CHAIN.get("rpc_wss", "")
RPC_HTTP = rpc_http_env if rpc_http_env is not None else CHAIN.get("rpc_http", "")
RPC_TIMEOUT = float(CHAIN.get("request_timeout_sec", 6))
NET = CHAIN.get("network", "finney")
BLOCK_HASH_CACHE_MAX = int(CHAIN.get("block_hash_cache", 1024))

# PoG scheduling
STEP = int(POG.get("exec_every_blocks", 5))
POG_INTERVAL_BLOCKS = int(POG.get("pog_interval_blocks", 25))
HEAD_TTL_SEC = float(POG.get("finalized_cache_ttl_sec", 10.0))
RPC_BACKOFF_SEC = float(POG.get("rpc_backoff_sec", 20.0))

# Allocation grace period: skip cleanup for this many seconds after allocation
# Prevents race condition where API hasn't synced allocation status yet
alloc_grace_env = _env_float("MINER_ALLOCATION_GRACE_SEC", None)
ALLOCATION_GRACE_SEC = float(alloc_grace_env if alloc_grace_env is not None else POG.get("allocation_grace_sec", 120.0))

SSH_CFG = CFG.get("ssh_config", {})
AXON_IP = _env("MINER_AXON_HOST") or SSH_CFG.get("host")
AXON_PORT = _env_int("MINER_AXON_PORT", SSH_CFG.get("port"))
SSH_PORT = _env_int("MINER_SSH_PORT", SSH_CFG.get("ssh-port"))

# PoG compute settings
GPU_INFO = CFG.get("gpu_performance", {}).get("GPU_AVRAM", {})
KIND = str(POG.get("anchor_kind", "micro")).lower()
BUF_MICRO = float(POG.get("buffer_micro", 0.02))
BUF_HEAVY = float(POG.get("buffer_heavy", 0.40))
N_CAP = int(POG.get("n_cap", 262144))
C_OPEN = int(POG.get("c_open_rows", 2))
PRIO_MICRO = int(POG.get("stream_micro_priority", 1))
PRIO_HEAVY = int(POG.get("stream_heavy_priority", 0))
# NOTE: STREAM_PRIO currently unused; kept for potential future use.
STREAM_PRIO = PRIO_MICRO if KIND == "micro" else PRIO_HEAVY

# Miner identity
WALLET_NAME = _env("MINER_WALLET_NAME") or MINER.get("wallet_name", "NI_core")
HOTKEY_NAME = _env("MINER_HOTKEY_NAME") or MINER.get("hotkey_name", "ni_vali1")
INST_UUID_CFG = _env("MINER_INST_UUID") or str(MINER.get("inst_uuid", "") or "").strip()
STATE_DIR = Path.home() / ".miner_validator"
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Confidential Compute Attestation (Intel TDX, NVIDIA CC)
CC_ATTESTATION_ENABLED = bool(POG.get("cc_attestation_enabled", False))
CC_ATTESTATION_MODE = str(POG.get("cc_attestation_mode", "mock") or "mock")

# --- Attestation Layer client config (miner -> attestation layer API) ---
AL_CFG = CFG.get("attestation_layer", {}) or {}
al_host_env = _env("ATTESTATION_LAYER_HOST")
al_port_env = _env_int("ATTESTATION_LAYER_PORT", None)
al_base_path_env = _env("ATTESTATION_LAYER_BASE_PATH")
al_url_env = _env("ATTESTATION_LAYER_URL")
al_auth_env = _env("ATTESTATION_LAYER_AUTH_TOKEN")
al_connect_to_env = _env_float("ATTESTATION_LAYER_CONNECT_TIMEOUT", None)
al_read_to_env = _env_float("ATTESTATION_LAYER_READ_TIMEOUT", None)

al_host = al_host_env or AL_CFG.get("host", "127.0.0.1")
al_port = al_port_env if al_port_env is not None else AL_CFG.get("port", 8080)
try:
    al_port = int(al_port)
except Exception:
    al_port = 8080
al_base_path = al_base_path_env or AL_CFG.get("base_path", "/v1") or "/v1"
al_base_path = al_base_path if al_base_path.startswith("/") else f"/{al_base_path}"
default_url = f"http://{al_host}:{al_port}{al_base_path}"
ATTESTATION_LAYER_URL = (al_url_env or AL_CFG.get("url") or default_url).rstrip("/")
AUTH_TOKEN = al_auth_env if al_auth_env is not None else AL_CFG.get("auth_token", "")
CONNECT_TO = float(al_connect_to_env if al_connect_to_env is not None else AL_CFG.get("connect_timeout_sec", 5))
READ_TO = float(al_read_to_env if al_read_to_env is not None else AL_CFG.get("read_timeout_sec", 30))


def load_or_create_identity() -> Tuple[str, str, Optional[str], Optional["object"]]:
    """
    Returns (pk_M_ss58, inst_uuid_hex, coldkey_ss58|None, wallet_obj|None).
    - pk_M (hotkey) and coldkey are derived from the configured wallet hotkey/coldkey.
    - inst_uuid is generated once per installation if missing (persisted to state).
    """
    import json

    wallet_obj = None
    pk_from_wallet: Optional[str] = None
    cold_from_wallet: Optional[str] = None

    try:
        import bittensor as bt

        wallet_obj = bt.wallet(name=WALLET_NAME, hotkey=HOTKEY_NAME)
        pk_from_wallet = wallet_obj.hotkey.ss58_address
        cpub = getattr(wallet_obj, "coldkeypub", None)
        if cpub is not None:
            cold_from_wallet = cpub.ss58_address
    except Exception as e:
        from .logging import log
        log("wallet_load_failed", level="warn", wallet=WALLET_NAME, hotkey=HOTKEY_NAME, err=str(e))
        wallet_obj = None

    cfg_inst = INST_UUID_CFG
    id_path = STATE_DIR / "miner_identity.json"
    inst: Optional[str] = None
    if id_path.exists():
        try:
            j = json.loads(id_path.read_text())
            inst = j.get("inst_uuid") or None
        except Exception:
            inst = None
    if not inst:
        inst = cfg_inst or None
    if not inst:
        inst = os.urandom(32).hex()  # 64-hex, stable per installation

    if pk_from_wallet is None or wallet_obj is None:
        wallet_root = (
            _env("BT_WALLET_PATH")
            or _env("BITTENSOR_WALLET_PATH")
            or str(Path.home() / ".bittensor" / "wallets")
        )
        expected_hotkey_path = str(Path(wallet_root) / WALLET_NAME / "hotkeys" / HOTKEY_NAME)
        raise RuntimeError(
            "Failed to load miner wallet/hotkey; cannot derive hotkey pk_M. "
            f"Expected hotkey file at: {expected_hotkey_path}. "
            f"Create keys with: btcli w new_coldkey --wallet.name {WALLET_NAME} ; "
            f"btcli w new_hotkey --wallet.name {WALLET_NAME} --wallet.hotkey {HOTKEY_NAME} ; "
            "or set MINER_WALLET_NAME/MINER_HOTKEY_NAME (or config.yaml: miner)."
        )

    pk = pk_from_wallet
    cold = cold_from_wallet

    state = {"inst_uuid": inst}
    try:
        id_path.write_text(json.dumps(state, indent=2))
    except Exception as e:
        from .logging import log
        log("identity_state_write_failed", level="warn", err=str(e))
    return pk, inst, cold, wallet_obj
