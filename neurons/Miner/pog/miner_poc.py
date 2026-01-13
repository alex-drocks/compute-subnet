#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Autonomous Miner (chain-beacon, scheduled, API push)
- Runs a proof every scheduled Bittensor block (default: every 5th block).
- Beacon = chain block hash; includes block meta in artifacts.
- Spawns one worker per GPU; order per GPU (unchanged):
  u0 commit -> u1 commit -> u0 openings -> u1 openings
  Artifacts per run (RUN_ROOT/<run_id>/):
  - receipt_u{0,1}_gpu{gid}.json
  - open_u{0,1}_gpu{gid}.npy
  - manifest.json (informational)
  - DONE
"""

import sys
from pathlib import Path

from .scheduler import main_loop, worker_entry

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "WORKER":
        params_json = Path(sys.argv[2])
        run_dir = Path(sys.argv[3])
        worker_entry(params_json, run_dir)
    else:
        main_loop()
