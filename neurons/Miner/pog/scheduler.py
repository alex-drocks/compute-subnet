# Suppress pynvml deprecation warning from PyTorch (must be before any torch import)
import warnings
warnings.filterwarnings("ignore", message=".*pynvml.*deprecated.*")

import json
import os
import random
import struct
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread
from typing import Optional

from .config import (
    CC_ATTESTATION_ENABLED,
    CC_ATTESTATION_MODE,
    BUF_HEAVY,
    BUF_MICRO,
    C_OPEN,
    GPU_INFO,
    KIND as CONFIG_KIND,
    NET,
    POLL_SEC,
    PRIO_HEAVY,
    PRIO_MICRO,
    RUN_ROOT,
    STATE_DIR,
    STEP,
    N_CAP,
    AXON_IP,
    AXON_PORT,
    SSH_PORT,
    load_or_create_identity,
)
from .api_client import get_alloc_state, post_json, send_heartbeat, post_attestation
from .hw import collect_hw_payload
from .proof import _fmtT, _now, run_single_u_fused, run_single_u_openings, set_identity
from .rpc import get_block_hash_cached, get_finalized_head, get_finalized_number_cached
from .util import sign_hotkey_payload, hotkey_to_pubkey_bytes, build_signature_header
from .logging import configure_logging, log, set_run_context, clear_run_context

KIND = CONFIG_KIND
_GPU_CACHE_TTL_SEC = float(os.getenv("MINER_GPU_CACHE_TTL", "5"))
_GPU_INFO_CACHE: dict[str, float | int | str | None] = {"ts": 0.0, "count": None, "name": None}


def _query_gpu_info() -> tuple[int, str]:
    gnum = int(
        subprocess.check_output(
            [sys.executable, "-c", "import torch; print(torch.cuda.device_count())"]
        )
        .decode()
        .strip()
    )
    gname = (
        subprocess.check_output(
            [sys.executable, "-c", "import torch; print(torch.cuda.get_device_name(0))"]
        )
        .decode()
        .strip()
    )
    return gnum, gname


def _get_gpu_info_cached(now: float | None = None) -> tuple[int, str]:
    """
    Cache GPU count/name briefly to avoid spawning python subprocesses every poll.
    Does not cache a missing GPU (count <= 0) so a returning device is detected quickly.
    """
    ts = time.time() if now is None else now
    cached_ts = float(_GPU_INFO_CACHE.get("ts") or 0.0)
    cached_count = _GPU_INFO_CACHE.get("count")
    cached_name = _GPU_INFO_CACHE.get("name")
    if (
        cached_count is not None
        and cached_name
        and (ts - cached_ts) < _GPU_CACHE_TTL_SEC
    ):
        return int(cached_count), str(cached_name)

    gnum, gname = _query_gpu_info()
    # Do not cache empty results; re-query next loop if no GPU.
    if gnum <= 0:
        _GPU_INFO_CACHE.update(ts=0.0, count=None, name=None)
        raise RuntimeError("No CUDA device detected")

    _GPU_INFO_CACHE.update(ts=ts, count=gnum, name=gname)
    return gnum, gname


# ---------- sizing ----------
def compute_n_from_buffer(gname: str) -> tuple[int, float, float, float]:
    buffer = BUF_MICRO if KIND == "micro" else BUF_HEAVY
    vram_gb = GPU_INFO.get(gname)
    if vram_gb is None:
        try:
            import torch

            props = torch.cuda.get_device_properties(0)
            vram_gb = round(props.total_memory / (1024**3))
        except Exception:
            vram_gb = 24
    vram_gb = float(vram_gb)
    vram_bytes = vram_gb * (1024**3)
    tgt = buffer * vram_bytes
    BYTES_PER_ALL = 8.0
    raw_n = int((tgt / BYTES_PER_ALL) ** 0.5)
    raw_n = (raw_n // 32) * 32
    n = max(256, min(raw_n, N_CAP))
    used = BYTES_PER_ALL * (n**2)
    return n, buffer, tgt, used


# ---------- worker ----------
def worker_entry(params_json_path: Path, run_dir: Path):
    os.environ.setdefault("CUDA_MODULE_LOADING", "EAGER")
    os.environ.setdefault("CUDA_DISABLE_PTX_JIT", "1")
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "max_split_size_mb:1024,expandable_segments:True")
    for v in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "BLIS_NUM_THREADS",
    ):
        os.environ.setdefault(v, "1")

    import hashlib
    import torch

    task = json.loads(params_json_path.read_text())
    gid = int(task["gpu_idx"])
    n = int(task["shape"]["n"])
    r2 = int(task.get("sampling", {}).get("c_open_rows", 2))
    run_id = str(task.get("run_id"))
    priority = int(task.get("priority", 0))
    pk_M = str(task["pk_M"])
    inst_uuid = str(task["inst_uuid"])
    epoch = int(task.get("epoch", 1))
    slot = int(task.get("slot", 1))
    beacon_hex = str(task["beacon_hex"])
    beacon_meta = task.get("beacon_meta", None)

    # load wallet for signing and set module-level identity for API posts
    _, _, _, wallet = load_or_create_identity()
    configure_logging()
    set_identity(pk_M, inst_uuid, wallet)
    set_run_context(inst_uuid, pk_M, run_id)

    t0 = _now()
    log(
        "worker_boot",
        level="debug",
        gpu_idx=gid,
        pid=os.getpid(),
        n=n,
        priority=priority,
        beacon_meta=beacon_meta,
    )
    import torch as _torch

    _torch.cuda.set_device(0)
    log("cuda_ready", level="debug", gpu_idx=gid, device="cuda:0")

    # Optional warmup
    try:
        import fused_prf_gemm_ext_fast as fpg  # type: ignore

        warmN = 1024 if n >= 1024 else max(256, (n // 2) // 32 * 32)
        Cw, rootw, flatw = fpg.fused_prf_gemm_commit_fast(0xDEC0DECAFEBABE, int(warmN), 0)
        _ = float(Cw[0, 0].to("cpu"))
        log("warmup_done", level="debug", gpu_idx=gid, warmN=int(warmN))
    except Exception as e:
        log("warmup_skipped", level="debug", gpu_idx=gid, err=str(e))

    # seeds (V2 includes inst_uuid)
    pk_bytes = hotkey_to_pubkey_bytes(pk_M)
    seed_all0 = hashlib.sha256(
        b"SEED_V2"
        + pk_bytes
        + bytes.fromhex(inst_uuid)
        + struct.pack("<III", epoch, slot, gid)
        + bytes.fromhex(beacon_hex)
    ).digest()

    # u = 0
    log("u0_start", level="debug", gpu_idx=gid, n=n)
    root0, flat0, C0, T_commit0, ts0 = run_single_u_fused(
        n, seed_all0, 0, gid, run_id, run_dir, priority, t0, beacon_meta
    )
    t0_th = Thread(
        target=run_single_u_openings,
        args=(n, r2, root0, flat0, C0, 0, gid, run_id, run_dir, T_commit0, t0, beacon_meta),
    )

    # u = 1 chained
    seed_all1 = hashlib.sha256(b"CHAIN_U1" + seed_all0 + root0).digest()
    log("u1_start", level="debug", gpu_idx=gid, n=n)
    root1, flat1, C1, T_commit1, ts1 = run_single_u_fused(
        n, seed_all1, 1, gid, run_id, run_dir, priority, t0, beacon_meta
    )
    t1_th = Thread(
        target=run_single_u_openings,
        args=(n, r2, root1, flat1, C1, 1, gid, run_id, run_dir, T_commit1, t0, beacon_meta),
    )

    t0_th.start()
    t1_th.start()
    t0_th.join()
    t1_th.join()

    delta = ts1 - ts0
    log("gpu_delta", level="info", gpu_idx=gid, delta_sec=round(delta, 4))
    clear_run_context()


# ---------- manifest (informational) ----------
def make_manifest(
    run_dir: Path,
    run_id: str,
    gnum: int,
    n: int,
    r2: int,
    gpu_name: str,
    pk_M: str,
    inst_uuid: str,
    beacon_meta: dict,
):
    import hashlib

    expected = []
    for gid in range(gnum):
        expected += [
            f"receipt_u0_gpu{gid}.json",
            f"receipt_u1_gpu{gid}.json",
            f"open_u0_gpu{gid}.npy",
            f"open_u1_gpu{gid}.npy",
        ]
    sha = {}
    for f in expected:
        p = run_dir / f
        if p.exists():
            h = hashlib.sha256()
            with open(p, "rb") as r:
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    h.update(chunk)
            sha[f] = h.hexdigest()

    manifest = {
        "inst_uuid": inst_uuid,
        "pk_M": pk_M,
        "run_id": run_id,
        "gpu_name": gpu_name,
        "gpu_num": gnum,
        "n": n,
        "c_open_rows": r2,
        "device": gpu_name,
        "expected": expected,
        "sha256": sha,
        "version": "v1",
        "beacon": beacon_meta,
        "epoch": 1,
        "slot": 1,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))


# ---------- main scheduler loop ----------
def main_loop():
    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    pk_M, inst_uuid, coldkey, wallet = load_or_create_identity()
    configure_logging()
    last_done_b = -1
    log("miner_autonomous", run_root=str(RUN_ROOT), network=NET, step=STEP)

    while True:
        # use cached finalized head number to reduce RPC load / respect backoff
        fnum = get_finalized_number_cached()
        if fnum is None:
            time.sleep(POLL_SEC)
            continue

        # run only on multiples of STEP
        if (fnum % STEP) != 0:
            time.sleep(POLL_SEC)
            continue
        b = fnum
        if b <= last_done_b:
            time.sleep(POLL_SEC)
            continue

        # beacon / exec meta
        try:
            b_hash = get_block_hash_cached(b)
            exec_hash, exec_num = get_finalized_head()
        except Exception as e:
            log("beacon_query_failed", level="warn", b=b, err=str(e))
            time.sleep(POLL_SEC)
            continue

        beacon_hex = b_hash[2:] if str(b_hash).startswith("0x") else str(b_hash)
        beacon_meta = {
            "network": NET,
            "b_num": b,
            "b_hash": b_hash,
            "exec_num": exec_num,
            "exec_hash": exec_hash,
        }

        # GPU info (cached to avoid spawning a python subprocess every poll)
        try:
            gnum, gpu_name = _get_gpu_info_cached()
        except Exception as e:
            log("cuda_query_failed", level="warn", err=str(e))
            time.sleep(5)
            continue

        # heartbeat + allocation state (pre-run only)
        hw_static, hw_live = collect_hw_payload()
        hotkey_payload = {
            "purpose": "heartbeat_v1",
            "inst_uuid": inst_uuid,
            "hotkey": pk_M,
            "ts": int(time.time()),
            "beacon_bnum": b,
        }
        hotkey_signature = sign_hotkey_payload(hotkey_payload, wallet)
        if not hotkey_signature:
            log("heartbeat_skipped_no_sig", level="warn")
            time.sleep(POLL_SEC)
            continue
        send_heartbeat(
            inst_uuid,
            pk_M,
            coldkey,
            hw_static,
            hw_live,
            AXON_IP,
            AXON_PORT,
            SSH_PORT,
            hotkey_payload,
            hotkey_signature,
            None,
        )

        # optional CC attestation (Intel TDX, NVIDIA CC - mock for now)
        if CC_ATTESTATION_ENABLED:
            att_payload = {
                "purpose": "attestation_v1",
                "inst_uuid": inst_uuid,
                "hotkey": pk_M,
                "ts": int(time.time()),
                "beacon_bnum": b,
                "mode": CC_ATTESTATION_MODE,
                "quote": f"mock_quote_{b}",
            }
            att_sig = sign_hotkey_payload(att_payload, wallet)
            if att_sig:
                post_attestation(
                    {
                        "inst_uuid": inst_uuid,
                        "pk_M": pk_M,
                        "attestation_payload": att_payload,
                        "attestation_signature": att_sig,
                    }
                )

        alloc_state: Optional[str] = get_alloc_state(pk_M, wallet)

        # Write allocation state to shared file for main miner process
        try:
            alloc_state_file = STATE_DIR / "alloc_state.json"
            alloc_state_file.write_text(json.dumps({
                "alloc_state": alloc_state,
                "ts": time.time(),
                "hotkey": pk_M
            }))
        except Exception:
            pass  # Non-critical, main miner can fall back to API

        # allocation-driven kind + priority
        effective_kind = "heavy"
        if isinstance(alloc_state, str) and alloc_state.lower() == "allocated":
            effective_kind = "micro"

        global KIND
        KIND = effective_kind

        # sizing (single n for all GPUs)
        n, _, _, _ = compute_n_from_buffer(gpu_name)
        r2 = C_OPEN
        priority = PRIO_MICRO if KIND == "micro" else PRIO_HEAVY

        # per-run directory
        run_id = f"b{b}_{int(time.time())}_{random.randrange(1 << 16):04x}"
        run_dir = RUN_ROOT / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "RUNNING").write_text(time.strftime("%Y-%m-%d %H:%M:%S"))
        run_t0 = time.time()

        set_run_context(inst_uuid, pk_M, run_id)
        log("run_start", b_num=b, n=n, gpus=gnum, device=gpu_name)

        # announce (advisory)
        announce_body = {
            "inst_uuid": inst_uuid,
            "pk_M": pk_M,
            "run_id": run_id,
            "b_num": b,
            "gpu_num": gnum,
            "gpu_name": gpu_name,
            "n": n,
            "c_open_rows": r2,
        }
        announce_headers = build_signature_header("run_announce_v1", announce_body, wallet, pk_M)
        post_json("/run/announce", announce_body, headers_extra=announce_headers)

        # spawn per-GPU workers
        procs = []
        for gid in range(gnum):
            task = {
                "inst_uuid": inst_uuid,
                "pk_M": pk_M,
                "run_id": run_id,
                "epoch": 1,
                "slot": 1,
                "gpu_idx": gid,
                "shape": {"n": n},
                "sampling": {"c_open_rows": r2},
                "priority": priority,
                "beacon_hex": beacon_hex,
                "beacon_meta": beacon_meta,
            }
            params_path = run_dir / f"task_gpu{gid}.json"
            params_path.write_text(json.dumps(task))
            env = os.environ.copy()
            env["CUDA_VISIBLE_DEVICES"] = str(gid)
            cmd = [
                sys.executable,
                "-m",
                "neurons.Miner.pog.miner_poc",
                "WORKER",
                str(params_path),
                str(run_dir),
            ]
            p = subprocess.Popen(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            log("worker_spawn", level="debug", gpu_idx=gid, pid=p.pid)
            procs.append(p)

        rc_sum = 0
        for gid, p in enumerate(procs):
            p.wait()
            rc = p.returncode or 0
            rc_sum |= rc
            log("worker_exit", level="debug", gpu_idx=gid, rc=rc)

        # manifest
        try:
            make_manifest(run_dir, run_id, gnum, n, r2, gpu_name, pk_M, inst_uuid, beacon_meta)
        except Exception as e:
            (run_dir / "ERROR").write_text(f"manifest error: {e}")

        (run_dir / "RUNNING").unlink(missing_ok=True)
        (run_dir / "DONE").write_text("ok\n")

        wall_clock_sec = round(time.time() - run_t0, 3)
        log("run_done", level="success", rc_sum=rc_sum, wall_clock_sec=wall_clock_sec)
        complete_body = {"inst_uuid": inst_uuid, "pk_M": pk_M, "run_id": run_id}
        complete_headers = build_signature_header("run_complete_v1", complete_body, wallet, pk_M)
        post_json("/run/complete", complete_body, headers_extra=complete_headers)
        last_done_b = b
        clear_run_context()
        time.sleep(POLL_SEC)
