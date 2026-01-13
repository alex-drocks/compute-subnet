SN27 Neuron Integration (Miner + Validator)
===========================================

This package contains the SN27 miner and validator implementations wired to the
PoG3 validation API and the vendored PoG3 miner client. The main entrypoints
live under `neurons/`:

- `neurons/miner.py`
- `neurons/validator.py`
- `neurons/RSAEncryption.py`
- `neurons/Miner/pog/*`
- `neurons/Validator/*`

Prerequisites
-------------

- Python 3.10 or 3.11 (matching the provided wheels).
- CUDA‑capable GPU with recent NVIDIA drivers.
- `pip` and `python3` available on PATH.

CUDA Extension / Wheel
----------------------

The PoG3 miner client uses the `fused_prf_gemm_ext_fast` CUDA extension. The
compiled wheels are provided under:

- `install/wheels/fused_prf_gemm_ext_fast-*-cp310-*.whl`
- `install/wheels/fused_prf_gemm_ext_fast-*-cp311-*.whl`

To install the extension and the base `miner` package used by the PoG3 client,
run from the repo root:

```bash
pip3 install .
```

On Linux x86_64 with CPython 3.10/3.11, this installs the matching
`fused_prf_gemm_ext_fast` wheel from `install/wheels/`.

If you prefer the helper script, you can still use:

```bash
./install/install_miner.sh
```

This script:

1. Detects your Python tag (`cp310` / `cp311`) and installs the matching
   `fused_prf_gemm_ext_fast` wheel (or falls back to a generic wheel).
2. Runs `pip3 install .` to expose the `miner` package under `src/miner`.

After this, imports like `import fused_prf_gemm_ext_fast as fpg` and
`python3 -m miner.miner_poc` will work.

SN27 Miner Setup
----------------

1. Ensure your SN27 miner environment has:
   - A funded Bittensor wallet (coldkey / hotkey).
   - Docker + NVIDIA container runtime available (as required by the compute
     subnet miner code).

2. Configure environment for the SN27 miner + PoG3 client:

   - Use `neurons/.env.miner` as a template, e.g.:

     - `MINER_WALLET_NAME`, `MINER_HOTKEY_NAME`
     - `MINER_AXON_HOST`, `MINER_AXON_PORT`, `MINER_SSH_PORT`, `MINER_TEST_SSH_PORT`
     - `VALIDATOR_API_URL`, `VALIDATOR_API_AUTH_TOKEN`
     - `MINER_LOG_LEVEL`, `MINER_LOG_JSON`

   - Or pass equivalent environment variables directly.

3. Make sure `neurons/config.yaml` matches your network (chain endpoints,
   schedule, gpu_performance, api settings).

4. Run the SN27 miner:

```bash
python3 -m neurons.miner
```

The miner will:

- Start the compute‑subnet axon.
- Launch the PoG3 loop via `neurons.Miner.pog.start_pog_loop(...)` using the
  same wallet / hotkey / axon / SSH config.

SN27 Validator Setup
--------------------

1. Configure environment for the SN27 validator:

   - Use `neurons/.env.validator` as a template, e.g.:

     - `WANDB_API_KEY`
     - `DEALLOCATION_NOTIFY_URL`, `STATUS_NOTIFY_URL`
     - `SQLITE_DB_PATH`, `WEBHOOKS_SECRET`
     - Validation API URL/timeout overrides if needed

2. Ensure `neurons/config.yaml` is present and contains:

   - `subnet_config` (emission, gpu_weights, reliability_weight).
   - `gpu_performance` and `gpu_time_models`.
   - `merkle_proof` bounds (`n_cap`, `c_open_rows`, etc.).

3. Run the SN27 validator:

```bash
python3 -m neurons.validator
```

Install Scripts
---------------

The `install/` directory is generic and belongs at the repo root. Keep:

- `install/install_miner.sh`
- `install/wheels/*`

The subnet‑27 code expects the CUDA extension and `miner` package to be
installed in the same environment. The `install_miner.sh` script is the
canonical way to do that.

Notes
-----

- The PoG worker spawn module path in `neurons/Miner/pog/scheduler.py` is:

  ```python
  cmd = [sys.executable, "-m", "neurons.Miner.pog.miner_poc", "WORKER", ...]
  ```

- The SN27 miner and validator both treat the SN27 CLI/config as primary, then
  environment variables, then `config.yaml` as fallback for shared PoG and API
  settings.
