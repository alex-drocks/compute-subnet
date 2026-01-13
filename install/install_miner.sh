#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(dirname "$0")/.."
WHEEL_DIR="$REPO_ROOT/install/wheels"

echo "[1] Installing CUDA extension wheel"
PY_TAG=$(python3 - <<'PY'
import sys
major, minor = sys.version_info[:2]
print(f"cp{major}{minor}")
PY
)
WHEEL=$(ls "${WHEEL_DIR}"/fused_prf_gemm_ext_fast-*${PY_TAG}*.whl 2>/dev/null | head -n 1 || true)
if [ -z "$WHEEL" ]; then
  echo "No matching wheel for Python tag ${PY_TAG} found in ${WHEEL_DIR}; attempting generic install."
  pip3 install --upgrade "${WHEEL_DIR}"/fused_prf_gemm_ext_fast-*.whl
else
  echo "Using wheel: $WHEEL"
  pip3 install --upgrade "$WHEEL"
fi

echo "[2] Installing NI-Compute package (includes neurons and compute modules)"
pip3 install "$REPO_ROOT"

echo "[3] Installation complete!"
echo "   Start miner: python3 neurons/miner.py --wallet.name <name> --wallet.hotkey <hotkey>"
echo "   PoG3 worker module 'miner.miner_poc' is used internally by the scheduler"
