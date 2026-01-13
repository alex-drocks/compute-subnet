import gzip
import hashlib
import json
import struct
import time
from pathlib import Path
from typing import List, Optional

import numpy as np

from .api_client import post_json, post_file
from .util import build_signature_header
from .logging import log

# -------- crypto domains --------
D_LEAF32 = b"ROW_HASH_V1"   # domain for Merkle leaves
D_PRE = b"PREH32_V1"        # domain for pre-commit/receipt

# module-level identity for API posts
_PK_M: Optional[str] = None
_INST_UUID: Optional[str] = None
_WALLET = None


def set_identity(pk_M: str, inst_uuid: str, wallet=None) -> None:
    global _PK_M, _INST_UUID, _WALLET
    _PK_M, _INST_UUID, _WALLET = pk_M, inst_uuid, wallet


def _now() -> float:
    return time.perf_counter()


def _fmtT(t0: float) -> str:
    return f"[T={(_now() - t0):.3f}s]"


# ---------- Merkle helpers (unchanged) ----------
def build_merkle_from_leaves(leaves: List[bytes]):
    if not leaves:
        raise ValueError("no leaves")
    level = leaves[:]
    tree_levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if (i + 1) < len(level) else level[i]
            nxt.append(hashlib.sha256(a + b).digest())
        level = nxt
        tree_levels.append(level)
    root = tree_levels[-1][0]
    flat = b"".join(b for lvl in tree_levels for b in lvl)
    return root, flat


def build_merkle_proof_from_flat(flat: bytes, idx: int, total: int) -> list[bytes]:
    proof, off, width = [], 0, total
    while width > 1:
        sib = idx ^ 1
        if sib >= width:
            sib = idx
        proof.append(flat[(off + sib) * 32 : (off + sib + 1) * 32])
        off += width
        idx //= 2
        width = (width + 1) // 2
    return proof


def fs_sample_unique(T: bytes, label: bytes, modulo: int, count: int) -> List[int]:
    seen, out, ctr = set(), [], 0
    while len(out) < count:
        dig = hashlib.sha256(T + label + struct.pack("<I", ctr)).digest()
        v = int.from_bytes(dig, "little") % modulo
        if v not in seen:
            seen.add(v)
            out.append(v)
        ctr += 1
    return out


# ---------- progress printing ----------
def write_progress(run_dir: Path, u: int, gid: int, stage: str, pct: float, info: dict | None, t0: float):
    rec = {"stage": stage, "pct": float(pct), "t": time.time(), "subseq": u, "gpu": gid}
    if info:
        rec.update(info)
    try:
        (run_dir / f"progress_u{u}_gpu{gid}.json").write_text(json.dumps(rec))
    except Exception:
        pass
    log(
        "proof_stage",
        level="debug",
        stage=stage,
        pct=round(pct * 100.0, 1),
        elapsed_sec=round(_now() - t0, 3),
        gpu_idx=gid,
        u=u,
        **(info or {}),
    )


# ---------- GPU stage (math unchanged; adds inst_uuid; SEED_V2) ----------
def run_single_u_fused(
    n: int,
    seed_all: bytes,
    u: int,
    gid: int,
    run_id: str,
    run_dir: Path,
    stream_priority: int,
    t0: float,
    beacon_meta: Optional[dict] = None,
):
    import torch
    import fused_prf_gemm_ext_fast as fpg  # type: ignore

    write_progress(run_dir, u, gid, "start", 0.00, {"n": n}, t0)
    seed_u64 = int.from_bytes(seed_all[:8], "little")
    C, root_cpu, flat_cpu = fpg.fused_prf_gemm_commit_fast(seed_u64, int(n), 0)

    root = root_cpu.contiguous().numpy().tobytes()
    flat = flat_cpu.contiguous().numpy().tobytes()
    write_progress(run_dir, u, gid, "fused_gemm_done", 0.70, {"dt": round(_now() - t0, 3)}, t0)

    T_commit = hashlib.sha256(
        D_PRE + seed_all + root + struct.pack("<I", u) + struct.pack("<I", n) + run_id.encode()
    ).digest()

    ts_ns = time.time_ns()
    receipt = {
        "inst_uuid": _INST_UUID,
        "pk_M": _PK_M,
        "run_id": run_id,
        "gpu_idx": gid,
        "u": u,
        "ts_ns": ts_ns,
        "root": root.hex(),
        "T_commit": T_commit.hex(),
    }
    if beacon_meta:
        receipt["beacon"] = beacon_meta
    (run_dir / f"receipt_u{u}_gpu{gid}.json").write_text(json.dumps(receipt))
    write_progress(run_dir, u, gid, "receipt_posted", 0.90, {"file": f"receipt_u{u}_gpu{gid}.json"}, t0)

    # push receipt (non-blocking for proof logic)
    if _PK_M and _INST_UUID and beacon_meta and "b_num" in beacon_meta:
        body = {
            "inst_uuid": _INST_UUID,
            "pk_M": _PK_M,
            "run_id": run_id,
            "gpu_idx": gid,
            "u": u,
            "root": receipt["root"],
            "T_commit": receipt["T_commit"],
            "b_num": int(beacon_meta["b_num"]),
        }
        headers = build_signature_header("run_receipt_v1", body, _WALLET, _PK_M)
        post_json(
            "/receipt",
            body,
            headers_extra=headers,
        )

    return root, flat, C, T_commit, ts_ns * 1e-9


def run_single_u_openings(
    n: int,
    r2: int,
    root: bytes,
    flat: bytes,
    C,
    u: int,
    gid: int,
    run_id: str,
    run_dir: Path,
    T_commit: bytes,
    t0: float,
    beacon_meta: Optional[dict] = None,
) -> bool:
    import torch
    import numpy as np

    t_open = _now()

    open_rows = fs_sample_unique(T_commit, b"Crows.open", n, r2)
    idx_cuda = torch.tensor(open_rows, device=C.device, dtype=torch.long)
    rows_dev = C.index_select(0, idx_cuda).contiguous()
    rows_cpu = torch.empty((len(open_rows), n), dtype=torch.float32, device="cpu", pin_memory=True)
    rows_cpu.copy_(rows_dev, non_blocking=True)

    proofs = {int(r): [p.hex() for p in build_merkle_proof_from_flat(flat, int(r), n)] for r in open_rows}
    torch.cuda.synchronize()
    rows_np = rows_cpu.numpy()

    C_open = []
    for i, r in enumerate(open_rows):
        C_open.append({"row_idx": int(r), "row": rows_np[i], "path": proofs[int(r)]})

    out = {
        "inst_uuid": _INST_UUID,
        "pk_M": _PK_M,
        "run_id": run_id,
        "subseq": u,
        "roots": {"dC_rows": root.hex()},
        "T_commit": T_commit.hex(),
        "shape": {"n": n},
        # store plain JSON (no pickle) to avoid unsafe loads on validator
        "C_open": [
            {
                "row_idx": int(entry["row_idx"]),
                "row": np.asarray(entry["row"], dtype=np.float32).tolist(),
                "path": entry["path"],
            }
            for entry in C_open
        ],
        "hash_mode": "sha256_row_v1",
    }
    if beacon_meta:
        out["beacon"] = beacon_meta
    blob_path = run_dir / f"open_u{u}_gpu{gid}.json.gz"
    compressed = gzip.compress(json.dumps(out, separators=(",", ":")).encode("utf-8"))
    blob_path.write_bytes(compressed)

    write_progress(
        run_dir,
        u,
        gid,
        "saved",
        1.00,
        {"blob": f"open_u{u}_gpu{gid}.npy", "dt_open": round(_now() - t_open, 3)},
        t0,
    )

    # push blob
    if _PK_M and _INST_UUID and beacon_meta and "b_num" in beacon_meta:
        fields = {
            "inst_uuid": _INST_UUID,
            "pk_M": _PK_M,
            "run_id": run_id,
            "gpu_idx": str(gid),
            "u": str(u),
            "b_num": str(int(beacon_meta["b_num"])),
        }
        headers = build_signature_header("run_opening_v1", fields, _WALLET, _PK_M)
        post_file(
            "/opening",
            fields,
            blob_path,
            headers_extra=headers,
        )

    return True
