# The MIT License (MIT)
# Copyright © 2023 Crazydevlegend
# Copyright © 2023 Rapiiidooo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import asyncio
import base64
import hashlib
import json
import os
import random
import tempfile
import threading
import traceback
import uuid
from datetime import datetime
from asyncio import AbstractEventLoop
from typing import Dict, Tuple, List, Any, Optional
from pathlib import Path

import yaml
import bittensor as bt
import time
import paramiko
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class EphemeralContainerHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Custom host key policy for ephemeral miner containers.

    Miner containers are dynamically allocated with new host keys each time.
    Since host keys cannot be pre-verified for ephemeral containers, this policy
    explicitly accepts them. This is intentional for the validator-miner SSH
    verification flow where containers are short-lived test instances.

    Security note: This is safe for our use case because:
    - Containers are ephemeral (new host key each allocation)
    - Connection details (host/port/password) come from trusted miner response
    - SSH is only used for GPU UUID verification, not sensitive operations
    """

    def missing_host_key(self, client, hostname, key):
        # Accept and store host key for ephemeral container connection
        # Security: Intentionally bypasses host key verification for ephemeral containers
        client._host_keys.add(hostname, key.get_name(), key)

import torch
from torch._C._te import Tensor  # type: ignore
from neurons import RSAEncryption as rsa
import concurrent.futures
from collections import defaultdict

import neurons.Validator.app_generator as ag
from compute import (
    SUSPECTED_EXPLOITERS_HOTKEYS,
    SUSPECTED_EXPLOITERS_COLDKEYS,
    __version_as_int__,
    validator_permit_stake,
    weights_rate_limit
)
from compute.axon import ComputeSubnetSubtensor
from compute.protocol import Allocate
from compute.pubsub import PubSubClient
from compute.utils.db import ComputeDb
from compute.utils.ed25519 import generate_ssh_keypair, get_ssh_public_key
from compute.utils.math import percent, force_to_float_or_default
from compute.utils.parser import ComputeArgPaser
from compute.utils.subtensor import is_registered, get_current_block, calculate_next_block_time
from compute.utils.version import try_update, get_local_version, version2number, get_remote_version
from compute.wandb.wandb import ComputeWandb
from neurons.Validator.database.allocate import update_miner_details, get_miner_details
from neurons.Validator.database.miner import select_miners, purge_miner_entries, update_miners
from neurons.Validator.health_check import perform_health_check
from neurons.Validator.template_check import perform_template_check
from neurons.Validator.database.pog import retrieve_stats, update_pog_stats, write_stats, purge_pog_stats
from neurons.Validator.api_client import ValidationApiClient, ApiInstance


def load_yaml_config(path: str) -> dict:
    """
    Safely load a YAML config file and return a dict.
    Returns {} on any error or if the root is not a mapping.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _safe_merge(existing: dict, incoming: dict) -> dict:
    """
    Safely merge incoming config into existing config.
    Only updates values that are non-empty in incoming.
    Handles nested dicts recursively.

    - Skip None values
    - Skip empty dicts/lists/strings
    - Preserve existing values when incoming is empty
    """
    if not isinstance(incoming, dict):
        return existing
    result = dict(existing) if existing else {}
    for key, new_val in incoming.items():
        old_val = result.get(key)
        # Skip empty/None values - preserve existing
        if new_val is None:
            continue
        if isinstance(new_val, dict) and not new_val:
            continue
        if isinstance(new_val, (list, str)) and len(new_val) == 0:
            continue
        # Recursive merge for nested dicts
        if isinstance(new_val, dict) and isinstance(old_val, dict):
            result[key] = _safe_merge(old_val, new_val)
        else:
            result[key] = new_val
    return result

class Validator:
    blocks_done: set = set()

    queryable_for_specs: dict = {}
    finalized_specs_once: bool = False

    total_current_miners: int = 0

    scores: Tensor
    stats: dict

    validator_subnet_uid: int

    _queryable_uids: Dict[int, bt.AxonInfo]

    loop: AbstractEventLoop

    @property
    def wallet(self) -> bt.wallet: # type: ignore
        return self._wallet

    @property
    def subtensor(self) -> ComputeSubnetSubtensor:
        return self._subtensor


    @property
    def metagraph(self) -> bt.metagraph: # type: ignore
        return self._metagraph

    @property
    def queryable(self):
        return self._queryable_uids

    @property
    def queryable_uids(self):
        return [uid for uid in self._queryable_uids.keys()]

    @property
    def queryable_axons(self):
        return [axon for axon in self._queryable_uids.values()]

    @property
    def queryable_hotkeys(self):
        return [axon.hotkey for axon in self._queryable_uids.values()]

    @property
    def current_block(self):
        return get_current_block(subtensor=self.subtensor)

    @property
    def miners_items_to_set(self):
        return set((uid, hotkey) for uid, hotkey in self.miners.items()) if self.miners else None

    def __init__(self):
        # Step 1: Parse the bittensor and compute subnet config
        self.config = self.init_config()

        # Setup extra args
        self.blacklist_hotkeys = {hotkey for hotkey in self.config.blacklist_hotkeys}
        self.blacklist_coldkeys = {coldkey for coldkey in self.config.blacklist_coldkeys}
        self.whitelist_hotkeys = {hotkey for hotkey in self.config.whitelist_hotkeys}
        self.whitelist_coldkeys = {coldkey for coldkey in self.config.whitelist_coldkeys}
        self.exploiters_hotkeys = {hotkey for hotkey in SUSPECTED_EXPLOITERS_HOTKEYS} if self.config.blacklist_exploiters else {}
        self.exploiters_coldkeys = {coldkey for coldkey in SUSPECTED_EXPLOITERS_COLDKEYS} if self.config.blacklist_exploiters else {}

        # Set custom validator arguments
        self.validator_specs_batch_size = self.config.validator_specs_batch_size
        self.validator_perform_hardware_query = self.config.validator_perform_hardware_query
        self.validator_whitelist_updated_threshold = self.config.validator_whitelist_updated_threshold

        # PoG cadence: parser config > env > config.yaml (pog.pog_interval_blocks) > default 25
        # This is loaded early before full config_data is available
        env_pog = os.getenv("POG_INTERVAL_BLOCKS")
        try:
            env_pog_val = int(env_pog) if env_pog else None
        except Exception:
            env_pog_val = None
        try:
            cfg_yaml = yaml.safe_load(open("config.yaml", "r")) or {}
            cfg_pog_val = int(cfg_yaml.get("pog", {}).get("pog_interval_blocks", 25))
        except Exception:
            cfg_pog_val = 25
        self.pog_interval_blocks = getattr(self.config, "pog_interval_blocks", None) or env_pog_val or cfg_pog_val or 25

        # Set up logging with the provided configuration and directory.
        bt.logging(config=self.config, logging_dir=self.config.full_path)
        bt.logging.info(f"Running validator for subnet: {self.config.netuid} on network: {self.config.subtensor.chain_endpoint} with config:")
        # Log the configuration for reference.
        bt.logging.info(self.config)

        # Step 2: Build Bittensor validator objects
        # These are core Bittensor classes to interact with the network.
        bt.logging.info("Setting up bittensor objects.")

        # The wallet holds the cryptographic key pairs for the validator.
        self._wallet = bt.wallet(config=self.config)
        bt.logging.info(f"Wallet: {self.wallet}")

        # The subtensor is our connection to the Bittensor blockchain.
        self._subtensor = ComputeSubnetSubtensor(config=self.config)
        bt.logging.info(f"Subtensor: {self.subtensor}")

        # The metagraph holds the state of the network, letting us know about other miners.
        self._metagraph = self.subtensor.metagraph(self.config.netuid)
        bt.logging.info(f"Metagraph: {self.metagraph}")

        # STEP 2B: Init Proof of GPU
        # Load configuration from YAML (before PubSubClient needs the values)
        config_file = "config.yaml"
        self.config_data = load_yaml_config(config_file)

        # Bring everything else into memory on init, too
        self.gpu_performance  = self.config_data.get("gpu_performance", {})
        self.gpu_time_models  = self.config_data.get("gpu_time_models", {})
        self.pog_config       = self.config_data.get("pog", {})

        # Validator block intervals and timeouts from config.yaml
        vali_cfg = self.config_data.get("validator", {})
        self._block_interval_hardware_info = int(vali_cfg.get("block_interval_hardware_info", 150))
        self._block_interval_miner_check = int(vali_cfg.get("block_interval_miner_check", 50))
        self._block_interval_sync_status = int(vali_cfg.get("block_interval_sync_status", 25))
        self._block_interval_token_refresh = int(vali_cfg.get("block_interval_token_refresh", 600))
        self._pubsub_timeout_sec = float(vali_cfg.get("pubsub_timeout_sec", 30.0))
        self._ssh_timeout_sec = int(vali_cfg.get("ssh_timeout_sec", 30))
        self._allocation_timeout_sec = int(vali_cfg.get("allocation_timeout_sec", 20))
        self._deallocation_timeout_sec = int(vali_cfg.get("deallocation_timeout_sec", 15))
        self._allocation_max_retries = int(vali_cfg.get("allocation_max_retries", 2))
        self._deallocation_max_retries = int(vali_cfg.get("deallocation_max_retries", 3))
        self._ssh_max_retries = int(vali_cfg.get("ssh_max_retries", 3))
        self._retry_backoff_sec = float(vali_cfg.get("retry_backoff_sec", 5))

        self.pubsub_client = PubSubClient(
            wallet=self.wallet,
            config=self.config,
            timeout=self._pubsub_timeout_sec,
            auto_refresh_interval=self._block_interval_token_refresh
        )

        # Validation API client (PoG3)
        self.api_client = ValidationApiClient(self.wallet)

        # Initialize the local db
        self.db = ComputeDb()
        self.miners: dict = select_miners(self.db)

        # Initialize wandb
        self.wandb = ComputeWandb(self.config, self.wallet, os.path.basename(__file__))

        # ── server_settings (now in validator section) ─────────────────────────────────────
        self.server_ip   = vali_cfg.get("server_ip",   "65.108.33.88")
        self.server_port = vali_cfg.get("server_port", "8000")
        self.server_url  = f"http://{self.server_ip}:{self.server_port}"

        self._last_cfg_pull    = 0.0
        self._cfg_pull_interval = vali_cfg.get("pull_interval", 300)

        # immediately apply the disk‐based subnet_config
        self.refresh_config_from_server()
        self.load_subnet_config()

        cpu_cores = os.cpu_count() or 1
        configured_max_workers = self.config_data.get("pog", {}).get("max_workers", 32)
        safe_max_workers = min((cpu_cores + 4)*4, configured_max_workers)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=safe_max_workers)
        self.results = {}
        self.gpu_task = None  # Track the GPU task

        # Initialize penalized_hotkeys as an empty list
        self.penalized_hotkeys = []

        # Initialize penalized_hotkeys_checklist as an empty list
        self.penalized_hotkeys_checklist = []

        # Allocation sync tracking (for syncing to validation API)
        self._allocation_sync_fail_count: int = 0  # Consecutive failure counter for logging

        # Step 3: Set up initial scoring weights for validation
        bt.logging.info("Building validation weights.")
        self.uids: list = self.metagraph.uids.tolist()
        self.last_uids: list = self.uids.copy()
        self.init_scores()
        self.sync_status()

        self.last_updated_block = self.current_block - (self.current_block % 100)

        # Init the thread.
        self.lock = threading.Lock()
        self.threads: List[threading.Thread] = []

        # Generate ephemeral access key
        self.ssh_private_key = generate_ssh_keypair()
        self.ssh_public_key = get_ssh_public_key(self.ssh_private_key)

    @staticmethod
    def init_config():
        """
        This function is responsible for setting up and parsing command-line arguments.
        :return: config
        """
        parser = ComputeArgPaser(description="This script aims to help validators with the compute subnet.")
        config = parser.config

        # Step 3: Set up logging directory
        # Logging is crucial for monitoring and debugging purposes.
        config.full_path = os.path.expanduser(
            "{}/{}/{}/netuid{}/{}".format(
                config.logging.logging_dir,
                config.wallet.name,
                config.wallet.hotkey,
                config.netuid,
                "validator",
            )
        )
        # Ensure the logging directory exists.
        if not os.path.exists(config.full_path):
            os.makedirs(config.full_path, exist_ok=True)

        # Return the parsed config.
        return config

    def init_prometheus(self):
        """
        Register the prometheus information on metagraph.
        :return: bool
        """
        # extrinsic prometheus is removed at 8.2.1

        bt.logging.info("Extrinsic prometheus information on metagraph.")

        success = self._subtensor.serve_prometheus(
            wallet=self.wallet,
            port=bt.core.settings.DEFAULTS.axon.port,
            netuid=self.config.netuid
        )
        if success:
            bt.logging.success(
                prefix="Prometheus served",
                suffix=f"<blue>Current version: {get_local_version()}</blue>"  # Corrected keyword
            )
        else:
            bt.logging.error("Prometheus initialization failed")
        return success

    def init_local(self):
        bt.logging.info(f"🔄 Syncing metagraph with subtensor.")
        self._metagraph = self.subtensor.metagraph(self.config.netuid)
        self.uids = self.metagraph.uids.tolist()

    def init_scores(self):
        self.scores = torch.zeros(len(self.uids), dtype=torch.float32)
        self.sync_scores()

    def refresh_config_from_server(self):
        """
        Fetch latest config from server and safely merge all sections.
        Only updates non-empty values, preserving local config when remote is empty.
        """
        # Skip remote config refresh if running on testnet
        if str(getattr(self.config.subtensor, "network", "")).lower() == "test":
            bt.logging.debug("Testnet detected — skipping remote config refresh.")
            return

        now = time.time()
        if now - self._last_cfg_pull < self._cfg_pull_interval:
            return
        self._last_cfg_pull = now

        try:
            r = requests.get(f"{self.server_url}/config", timeout=5)
            if r.status_code != 200:
                bt.logging.warning(f"Config fetch failed: HTTP {r.status_code}")
                return

            new_cfg = r.json().get("config", {})
            if not isinstance(new_cfg, dict):
                bt.logging.warning("Remote config payload was not a dict")
                return

            # Safe merge into config_data (preserves local values if remote is empty)
            self.config_data = _safe_merge(self.config_data, new_cfg)

            # Reload each section with validation
            self.load_subnet_config()
            self._load_validator_config()
            self._load_pog_config()

            # GPU configs (safe merge)
            if new_cfg.get("gpu_performance"):
                self.gpu_performance = _safe_merge(
                    self.gpu_performance, new_cfg["gpu_performance"]
                )
            if new_cfg.get("gpu_time_models"):
                self.gpu_time_models = _safe_merge(
                    self.gpu_time_models, new_cfg["gpu_time_models"]
                )

            # Reload attestation layer config in api_client if present
            if new_cfg.get("attestation_layer"):
                self.api_client.reload_config()

            bt.logging.debug("Config refresh complete")
        except Exception as e:
            bt.logging.warning(f"Config refresh error: {e}")

    def load_subnet_config(self):
        subnet_config = self.config_data.get("subnet_config", {})

        # Scheduling constants
        self.blocks_per_epoch = subnet_config.get("blocks_per_epoch", 120)
        self.max_challenge_blocks = subnet_config.get("max_challenge_blocks", 10)
        self.rand_delay_blocks_max = subnet_config.get("rand_delay_blocks_max", 5)
        self.allow_fake_sybil_slot = subnet_config.get("allow_fake_sybil_slot", False)
        self.sybil_eligible_hotkeys = set(
            subnet_config.get("sybil_check_eligible_hotkeys") or []
        )
        self.instant_validation = subnet_config.get("instant_validation", False)

        # Emission control
        self.total_miner_emission = float(subnet_config.get("total_miner_emission", 0.0))
        self.gpu_weights = subnet_config.get("gpu_weights", {})

        # Treasury configuration
        self.treasury_wallet_hotkey = subnet_config.get("treasury_wallet_hotkey", "")
        self.treasury_emission_share = float(subnet_config.get("treasury_emission_share", 0.0))

        # Other
        raw = subnet_config.get("reliability_weight", 0.5)  # 1.0 = full effect, 0.0 = ignore reliability
        try:
            self.reliability_weight = float(raw)
        except Exception:
            self.reliability_weight = 0.5
        if self.reliability_weight < 0.0:
            self.reliability_weight = 0.0
        elif self.reliability_weight > 1.0:
            self.reliability_weight = 1.0

        bt.logging.debug(f"🔧 Loaded subnet config:")
        bt.logging.debug(f"  total_miner_emission = {self.total_miner_emission}")

    def _load_validator_config(self):
        """Reload validator section config. Only updates valid non-empty values."""
        vali_cfg = self.config_data.get("validator", {})
        if not isinstance(vali_cfg, dict) or not vali_cfg:
            return

        def _safe_int(key, default, min_val=1):
            if key in vali_cfg:
                try:
                    val = int(vali_cfg[key])
                    return val if val >= min_val else default
                except (ValueError, TypeError):
                    pass
            return None  # None means don't update

        def _safe_float(key, default, min_val=0.0):
            if key in vali_cfg:
                try:
                    val = float(vali_cfg[key])
                    return val if val > min_val else default
                except (ValueError, TypeError):
                    pass
            return None

        # Update each value only if present and valid
        if (v := _safe_int("block_interval_hardware_info", 150)) is not None:
            self._block_interval_hardware_info = v
        if (v := _safe_int("block_interval_miner_check", 50)) is not None:
            self._block_interval_miner_check = v
        if (v := _safe_int("block_interval_sync_status", 25)) is not None:
            self._block_interval_sync_status = v
        if (v := _safe_int("block_interval_token_refresh", 600)) is not None:
            self._block_interval_token_refresh = v
        if (v := _safe_float("pubsub_timeout_sec", 30.0)) is not None:
            self._pubsub_timeout_sec = v
        if (v := _safe_int("ssh_timeout_sec", 30)) is not None:
            self._ssh_timeout_sec = v
        if (v := _safe_int("allocation_timeout_sec", 20)) is not None:
            self._allocation_timeout_sec = v
        if (v := _safe_int("deallocation_timeout_sec", 15)) is not None:
            self._deallocation_timeout_sec = v
        if (v := _safe_int("allocation_max_retries", 2, min_val=0)) is not None:
            self._allocation_max_retries = v
        if (v := _safe_int("deallocation_max_retries", 3, min_val=0)) is not None:
            self._deallocation_max_retries = v
        if (v := _safe_int("ssh_max_retries", 3, min_val=0)) is not None:
            self._ssh_max_retries = v
        if (v := _safe_float("retry_backoff_sec", 5.0)) is not None:
            self._retry_backoff_sec = v
        if (v := _safe_int("pull_interval", 60)) is not None:
            self._cfg_pull_interval = v

    def _load_pog_config(self):
        """Reload PoG section config. Only updates valid non-empty values."""
        pog_cfg = self.config_data.get("pog", {})
        if not isinstance(pog_cfg, dict):
            return

        # Merge full dict (preserves local keys not in remote)
        if pog_cfg:
            self.pog_config = _safe_merge(self.pog_config, pog_cfg)

        # Extract specific values with validation
        if "pog_interval_blocks" in pog_cfg:
            try:
                val = int(pog_cfg["pog_interval_blocks"])
                if val > 0:
                    self.pog_interval_blocks = val
            except (ValueError, TypeError):
                pass

    @staticmethod
    def pretty_print_dict_values(items: dict):
        for key, values in items.items():
            log = f"uid: {key}"

            for values_key, values_values in values.items():
                if values_key == "ss58_address":
                    values_values = values_values[:8] + (values_values[8:] and "...")
                try:
                    values_values = f"{float(values_values):.2f}"
                except Exception:
                    pass
                log += f" | {values_key}: {values_values}"

            bt.logging.trace(log)

    def update_allocation_wandb(self):
        hotkey_list = []
        # Instantiate the connection to the db
        cursor = self.db.get_cursor()
        try:
            # Retrieve all records from the allocation table
            cursor.execute("SELECT id, hotkey, details FROM allocation")
            rows = cursor.fetchall()
            for row in rows:
                id, hotkey, details = row
                hotkey_list.append(hotkey)
        except Exception as e:
            bt.logging.warning(f"An error occurred while retrieving allocation details: {e}")
        finally:
            cursor.close()

        # Update wandb
        try:
            self.wandb.update_allocated_hotkeys(hotkey_list, self.penalized_hotkeys)
        except Exception as e:
            bt.logging.warning(f"Error updating wandb: {e}")

    def sync_scores(self):
        # 1) Fetch latest PoG3 scores from DB and miner details
        existing_stats = retrieve_stats(self.db)
        miner_details_all = get_miner_details(self.db)

        # 2) Refresh queryable miners and reliability / penalization maps
        self._queryable_uids = self.get_queryable()
        try:
            valid_validator_hotkeys = self.get_valid_validator_hotkeys()
        except Exception as e:
            bt.logging.warning(f"Failed to compute valid validator hotkeys for penalization: {e}")
            valid_validator_hotkeys = []
        try:
            reliability_by_uid = self.wandb.get_reliability_scores()
        except Exception as e:
            bt.logging.warning(f"Failed to fetch reliability scores from wandb: {e}")
            reliability_by_uid = {}
        try:
            penalized_hotkeys = self.wandb.get_penalized_hotkeys_checklist(valid_validator_hotkeys, True)
        except Exception as e:
            bt.logging.warning(f"Failed to fetch penalized hotkeys from wandb: {e}")
            penalized_hotkeys = set()

        # 4) Compute final scores per UID (PoG3 base + reliability)
        self.stats = {}
        for uid in self.uids:
            try:
                hotkey = self.metagraph.axons[uid].hotkey

                # Unqueryable → zero out, clean PoG stats
                if uid not in self._queryable_uids:
                    prev = existing_stats.get(uid, {})
                    self.stats[uid] = {
                        "hotkey": hotkey,
                        "allocated": bool(prev.get("allocated", False)),
                        "own_score": True,
                        "score": 0.0,
                        "gpu_specs": None,
                        "reliability_score": float(prev.get("reliability_score", 0.0)),
                    }
                    self.scores[uid] = 0.0
                    cursor = self.db.get_cursor()
                    cursor.execute("DELETE FROM pog_stats WHERE hotkey = ?", (hotkey,))
                    cursor.close()
                    continue

                prev = existing_stats.get(uid, {})
                base_score = float(prev.get("score", 0.0)) / 100.0
                gpu_specs = prev.get("gpu_specs")
                allocated_flag = bool(prev.get("allocated", False))

                # Reliability score: prefer W&B aggregate, else keep local value, else neutral 1.0
                rel = reliability_by_uid.get(uid, prev.get("reliability_score", 1.0))
                try:
                    rel = float(rel)
                except Exception:
                    rel = 1.0
                if rel < 0.0:
                    rel = 0.0
                elif rel > 1.0:
                    rel = 1.0
                rel_weight = self.reliability_weight
                rel_multiplier = (1.0 - rel_weight) + (rel_weight * rel)

                # Apply reliability score
                final_score = float(base_score) * rel_multiplier

                # Penalization / missing miner details force zero
                if (
                    hotkey in penalized_hotkeys
                    or not isinstance(miner_details_all.get(hotkey), dict)
                    or not miner_details_all.get(hotkey)
                ):
                    final_score = 0.0

                # Store
                self.stats[uid] = {
                    "hotkey": hotkey,
                    "allocated": allocated_flag,
                    "own_score": True,
                    "score": final_score * 100.0,
                    "gpu_specs": gpu_specs,
                    "reliability_score": rel,
                }
                self.scores[uid] = final_score

            except KeyError as e:
                bt.logging.warning(f"KeyError occurred for UID {uid}: {str(e)}")
                self.scores[uid] = 0.0
                self.stats[uid] = {
                    "hotkey": self.metagraph.axons[uid].hotkey if uid < len(self.metagraph.axons) else "unknown",
                    "allocated": False,
                    "own_score": True,
                    "score": 0.0,
                    "gpu_specs": None,
                    "reliability_score": 0.0,
                }
            except Exception as e:
                bt.logging.warning(f"Unexpected exception for UID {uid}: {str(e)}")
                self.scores[uid] = 0.0
                self.stats[uid] = {
                    "hotkey": self.metagraph.axons[uid].hotkey if uid < len(self.metagraph.axons) else "unknown",
                    "allocated": False,
                    "own_score": True,
                    "score": 0.0,
                    "gpu_specs": None,
                    "reliability_score": 0.0,
                }

        # 5) Persist and re-push
        write_stats(self.db, self.stats)
        self.update_allocation_wandb()

        # 6) Logging - Summary at INFO, full table at DEBUG
        allocated_count = sum(1 for d in self.stats.values() if d.get("allocated"))
        scored_count = sum(1 for d in self.stats.values() if d.get("score", 0) > 0)
        bt.logging.info("-" * 80)
        bt.logging.info(f"MINER STATS: Total={len(self.stats)} | Allocated={allocated_count} | Scored={scored_count}")
        bt.logging.info("-" * 80)

        # Full per-miner table at DEBUG level only
        for uid, data in self.stats.items():
            hotkey_str = str(data.get("hotkey", "unknown"))
            gpu_specs = data.get("gpu_specs")
            if isinstance(gpu_specs, dict):
                gpu_name = gpu_specs.get("gpu_name", "Unknown GPU")
                num_gpus = gpu_specs.get("num_gpus", 0)
                gpu_str = f"{num_gpus} x {gpu_name}" if num_gpus > 0 else "No GPUs"
            else:
                gpu_str = "N/A"
            score_str = f"{float(data.get('score', 0.0)):.2f}"
            allocated = "yes" if data.get("allocated", False) else "no"
            log_entry = f"UID {uid}: {hotkey_str[:16]}... | {gpu_str} | score={score_str} | alloc={allocated}"
            bt.logging.debug(log_entry)
        bt.logging.debug(f"Scores: {self.scores.tolist()}")

    def sync_local(self):
        """
        Resync our local state with the latest state from the blockchain.
        Sync scores with metagraph.
        Get the current uids of all miners in the network.
        """
        self.metagraph.sync(subtensor=self.subtensor)
        self.uids = self.metagraph.uids.tolist()

    def _safe_get_metric(self, metric_array, default: float = 0.0) -> float:
        """Safely access metagraph metric for this validator's UID with bounds checking."""
        try:
            uid = self.validator_subnet_uid
            if uid is not None and 0 <= uid < len(metric_array):
                return float(metric_array[uid])
        except Exception:
            pass
        return default

    def sync_status(self):
        # Check if the validator is still registered
        self.validator_subnet_uid = is_registered(
            wallet=self.wallet,
            metagraph=self.metagraph,
            subtensor=self.subtensor,
            entity="validator",
        )

        # Check for auto update
        if self.config.auto_update:
            try_update()

        # Check if the validator has the prometheus info updated
        subnet_prometheus_version = self.metagraph.neurons[self.validator_subnet_uid].prometheus_info.version
        current_version = __version_as_int__
        if subnet_prometheus_version != current_version:
            self.init_prometheus()

    async def sync_allocation_status_to_api(self):
        """
        Sync full allocation status to the validation API.

        Always sends complete state of all miners (allocated vs free).
        This is simple, self-healing, and the overhead for 250-1000 keys
        every few seconds is negligible (~60KB).
        """
        try:
            # 1. Get current allocations from database
            cursor = self.db.get_cursor()
            try:
                cursor.execute("SELECT hotkey FROM allocation")
                rows = cursor.fetchall()
                current_allocations = {row[0] for row in rows}
            finally:
                cursor.close()

            # 2. Get all queryable miner hotkeys (with bounds checking)
            queryable_uids = self.get_queryable()
            hotkeys_len = len(self.metagraph.hotkeys)
            all_hotkeys = {
                self.metagraph.hotkeys[uid]
                for uid in queryable_uids
                if 0 <= uid < hotkeys_len
            }

            # 3. Build full state payload
            allocations = []
            for hk in all_hotkeys:
                state = "allocated" if hk in current_allocations else "free"
                allocations.append({"key": hk, "state": state})

            if not allocations:
                return  # No miners to sync

            # 4. Send to API
            result = self.api_client.sync_allocations(allocations)

            if result:
                allocated_count = sum(1 for a in allocations if a["state"] == "allocated")
                bt.logging.info(
                    f"Allocation sync: {allocated_count}/{len(allocations)} allocated"
                )
                self._allocation_sync_fail_count = 0
            else:
                self._allocation_sync_fail_count += 1
                bt.logging.warning(
                    f"Allocation sync failed (attempt {self._allocation_sync_fail_count})"
                )

        except Exception as e:
            self._allocation_sync_fail_count += 1
            bt.logging.error(f"Error in allocation sync: {e}")

    def sync_miners_info(self, queryable_tuple_uids_axons: List[Tuple[int, bt.AxonInfo]]):
        if queryable_tuple_uids_axons:
            current_miners = self.miners_items_to_set or set()
            for uid, axon in queryable_tuple_uids_axons:
                if (uid, axon.hotkey) not in current_miners:
                    try:
                        bt.logging.info(f"❌ Miner {uid}-{self.miners[uid]} has been deregistered. Clean up old entries.")
                        purge_miner_entries(self.db, uid, self.miners[uid])
                    except KeyError:
                        pass
                    bt.logging.info(f"✅ Setting up new miner {uid}-{axon.hotkey}.")
                    update_miners(self.db, [(uid, axon.hotkey)]),
                    self.miners[uid] = axon.hotkey
        else:
            bt.logging.warning(f"❌ No queryable miners (total registered: {len(self.uids)})")

    @staticmethod
    def filter_axons(queryable_tuple_uids_axons: list[tuple[int, bt.AxonInfo]]) -> dict[int, bt.AxonInfo]:
        """Filter the axons with uids_list, remove those with the same IP address."""
        # FIXME(CSN-904): this does not work as intended, disabling till we know what to do
        bt.logging.trace("Axon filtering disabled")
        return dict(queryable_tuple_uids_axons)

        # Set to keep track of unique identifiers
        valid_ip_addresses = set()

        # List to store filtered axons
        dict_filtered_axons = {}
        for uid, axon in queryable_tuple_uids_axons:
            ip_address = axon.ip

            if ip_address not in valid_ip_addresses:
                valid_ip_addresses.add(ip_address)
                dict_filtered_axons[uid] = axon
            else:
                bt.logging.debug(f"Skipping duplicated IP UID: {uid}")

        return dict_filtered_axons

    def filter_axon_version(self, dict_filtered_axons: dict):
        # Get the minimal miner version
        latest_version = version2number(get_remote_version(pattern="__minimal_miner_version__"))
        dict_filtered_axons_version = {}
        total_current_miners = self.total_current_miners or len(dict_filtered_axons)
        if total_current_miners == 0:
            return dict_filtered_axons

        updated_count = 0
        for uid, axon in dict_filtered_axons.items():
            if latest_version and latest_version <= axon.version:
                dict_filtered_axons_version[uid] = axon
                updated_count += 1
            else:
                bt.logging.trace(f"Skipping outdated UID {uid}: version {axon.version} < required {latest_version}")

        if percent(updated_count, total_current_miners) <= self.validator_whitelist_updated_threshold:
            bt.logging.info(
                f"Less than {self.validator_whitelist_updated_threshold}% miners are currently using the last version. Allowing all."
            )
            return dict_filtered_axons
        return dict_filtered_axons_version

    def is_blacklisted(self, neuron: bt.NeuronInfoLite):
        coldkey = neuron.coldkey
        hotkey = neuron.hotkey

        # Blacklist coldkeys that are blacklisted by user
        if coldkey in self.blacklist_coldkeys:
            bt.logging.info(f"Blacklisted recognized coldkey {coldkey} - with hotkey: {hotkey}")
            return True

        # Blacklist coldkeys that are blacklisted by user or by set of hotkeys
        if hotkey in self.blacklist_hotkeys:
            bt.logging.info(f"Blacklisted recognized hotkey {hotkey}")
            # Add the coldkey attached to this hotkey in the blacklisted coldkeys
            self.blacklist_hotkeys.add(coldkey)
            return True

        # Blacklist coldkeys that are exploiters
        if coldkey in self.exploiters_coldkeys:
            bt.logging.info(f"Blacklisted exploiter coldkey {coldkey} - with hotkey: {hotkey}")
            return True

        # Blacklist hotkeys that are exploiters
        if hotkey in self.exploiters_hotkeys:
            bt.logging.info(f"Blacklisted exploiter hotkey {hotkey}")
            # Add the coldkey attached to this hotkey in the blacklisted coldkeys
            self.exploiters_hotkeys.add(coldkey)
            return True
        return False

    def get_valid_queryable(self):
        valid_queryable = []
        self.total_current_miners = 0
        bt.logging.trace(f"All UIDs before filtering: {self.uids}")
        for uid in self.uids:
            neuron: bt.NeuronInfoLite = self.metagraph.neurons[uid]
            axon = self.metagraph.axons[uid]

            if neuron.axon_info.ip != "0.0.0.0" and not self.is_blacklisted(neuron=neuron):
                valid_queryable.append((uid, axon))
                self.total_current_miners += 1
            elif self.is_blacklisted(neuron=neuron):
                bt.logging.trace(f"Skipping blacklisted UID: {uid}")
            else:
                bt.logging.trace(f"Skipping inactive UID: {uid}")

        bt.logging.trace(f"Valid UIDs after filtering: {[uid for uid, _ in valid_queryable]}")

        return valid_queryable

    def get_queryable(self):
        queryable = self.get_valid_queryable()

        # Execute a cleanup of the stats and miner information if the miner has been dereg
        self.sync_miners_info(queryable)

        dict_filtered_axons = self.filter_axons(queryable_tuple_uids_axons=queryable)
        dict_filtered_axons = self.filter_axon_version(dict_filtered_axons=dict_filtered_axons)
        return dict_filtered_axons

    def get_valid_validator_hotkeys(self):
        valid_uids = []
        uids = self.metagraph.uids.tolist()
        for index, uid in enumerate(uids):
            if self.metagraph.total_stake[index] > validator_permit_stake:
                valid_uids.append(uid)
        valid_hotkeys = []
        for uid in valid_uids:
            neuron = self.subtensor.neuron_for_uid(uid, self.config.netuid)
            hotkey = neuron.hotkey
            valid_hotkeys.append(hotkey)
        return valid_hotkeys

    async def get_specs_wandb(self):
        """
        Retrieves hardware specifications from Wandb, updates the miner_details table,
        Entries not present in Wandb will increment no_specs_count and be removed after 2 fails.
        """
        bt.logging.info(f"💻 Hardware list of uids queried (Wandb): {list(self._queryable_uids.keys())}")

        # Retrieve specs from Wandb
        specs_dict = self.wandb.get_miner_specs(self._queryable_uids)

        # Collect the hotkeys present in Wandb this pass
        present_hotkeys = {hk for (hk, _specs) in specs_dict.values()}

        # Update the local db with the new data from Wandb
        update_miner_details(self.db, present_hotkeys, list(specs_dict.values()))

        self.finalized_specs_once = True

    @staticmethod
    def _parse_api_timestamp(ts_val: Any) -> float:
        if not ts_val:
            return 0.0
        try:
            ts_str = str(ts_val).replace("Z", "+00:00")
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return 0.0

    def _build_api_map(self, instances: List[ApiInstance]) -> dict[str, list[ApiInstance]]:
        api_map: dict[str, list[ApiInstance]] = {}
        for inst in instances:
            api_map.setdefault(inst.pk_M, []).append(inst)
        for pk, lst in api_map.items():
            lst.sort(key=lambda x: self._parse_api_timestamp(x.stats.get("updated_at")), reverse=True)
        return api_map

    @staticmethod
    def _is_allocated_state(state: Optional[str]) -> bool:
        return isinstance(state, str) and state.lower() == "allocated"

    @staticmethod
    def _score_from_api_status(status: str) -> float:
        st = (status or "").lower()
        if st in ("pass", "pending"):
            return 1.0
        return 0.0

    async def _fetch_remote_gpu(self, miner_info: dict) -> tuple[bool, Optional[str], Optional[str], int]:
        """
        Fetch primary GPU UUID and name over SSH. Returns (ok, uuid, name, num_gpus).
        Retries up to ssh_max_retries times with backoff on failure.
        """
        ssh_timeout = self._ssh_timeout_sec
        ssh_private_key = self.ssh_private_key
        max_retries = self._ssh_max_retries
        backoff_sec = self._retry_backoff_sec
        host = miner_info.get("host", "unknown")

        def _single_attempt():
            """Single SSH attempt - returns (ok, uuid, name, count) or raises."""
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(EphemeralContainerHostKeyPolicy())
            try:
                ssh.connect(
                    hostname=miner_info["host"],
                    port=int(miner_info.get("port", 22)),
                    username=miner_info["username"],
                    pkey=ssh_private_key,
                    timeout=ssh_timeout,
                )
                cmd = "nvidia-smi --query-gpu=uuid,name --format=csv,noheader,nounits"
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=ssh_timeout)
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                if err:
                    bt.logging.debug(f"nvidia-smi error on miner {host}: {err}")
                lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
                if not lines:
                    return False, None, None, 0
                first = lines[0].split(",")
                uuid_val = first[0].strip() if len(first) >= 1 else None
                name_val = first[1].strip() if len(first) >= 2 else None
                return True, uuid_val or None, name_val or None, len(lines)
            finally:
                ssh.close()

        for attempt in range(1, max_retries + 1):
            try:
                result = await asyncio.to_thread(_single_attempt)
                if result[0]:  # Success
                    return result
                # nvidia-smi returned empty - might be transient, retry
                if attempt < max_retries:
                    bt.logging.debug(
                        f"SSH GPU probe empty response from {host} "
                        f"(attempt {attempt}/{max_retries}), retrying..."
                    )
                    await asyncio.sleep(backoff_sec * attempt)
            except Exception as e:
                bt.logging.debug(
                    f"SSH GPU probe failed for {host} "
                    f"(attempt {attempt}/{max_retries}): {e}"
                )
                if attempt < max_retries:
                    await asyncio.sleep(backoff_sec * attempt)

        bt.logging.debug(f"SSH GPU probe exhausted all {max_retries} retries for {host}")
        return False, None, None, 0

    async def _validate_with_uid(self, uid: int, axon: bt.AxonInfo, api_map: dict, dendrite):
        """Wrapper to include uid in result for parallel processing."""
        res = await self._validate_single(axon, api_map, dendrite)
        return uid, axon.hotkey, res

    async def _validate_single(
        self,
        axon: bt.AxonInfo,
        api_map: dict[str, list[ApiInstance]],
        dendrite,
    ):
        hotkey = axon.hotkey
        gpu_uuid = None
        gpu_name = None
        gpu_count = 0
        api_status = "unknown"
        allocation_ok = False
        public_key = None
        base_score = 0.0

        best_inst = None
        inst_list = api_map.get(hotkey, [])
        if inst_list:
            best_inst = inst_list[0]
            api_status = (best_inst.current_status or "unknown").lower()

        # Early return for failed miners - no point doing allocation check
        if api_status not in ("pass", "pending"):
            bt.logging.debug(f"[{hotkey[:8]}] api_status={api_status}, skipping allocation check")
            return {
                "passed": False,
                "gpu_name": best_inst.primary_gpu_name if best_inst else None,
                "gpu_count": best_inst.gpu_count if best_inst else 0,
                "base_score": 0.0,
            }

        api_gpu_name = None
        api_gpu_count = 0
        if best_inst is not None:
            api_gpu_name = best_inst.primary_gpu_name
            api_gpu_count = best_inst.gpu_count

        alloc_state = None
        if best_inst is not None:
            try:
                raw_alloc = best_inst.stats.get("alloc_state")
                alloc_state = str(raw_alloc).lower() if raw_alloc is not None else None
            except Exception:
                alloc_state = None

        # Test containers use separate SSH port (4445) and per-validator naming
        # All validators can verify GPU UUID via test allocations, regardless of production allocation

        miner_info = None
        try:
            # Skip RSA key generation - send empty public_key, miner returns plain JSON
            # This is backwards compatible: old miners will fail gracefully, new miners return plain
            public_key = ""
            miner_info = await self.allocate_miner(axon, "", "", self.ssh_public_key, dendrite)
            allocation_ok = miner_info is not None
        except Exception as e:
            bt.logging.debug(f"[{hotkey[:8]}] allocation failed - {e}")
            allocation_ok = False
        bt.logging.debug(f"[{hotkey[:8]}] allocation={'OK' if allocation_ok else 'FAIL'}")

        # Use try/finally to guarantee deallocation whenever allocation succeeds
        try:
            if miner_info:
                try:
                    ok, uuid_val, name_val, count_val = await self._fetch_remote_gpu(miner_info)
                    bt.logging.debug(f"[{hotkey[:8]}] SSH probe: ok={ok}, uuid={uuid_val}, gpu={name_val}, count={count_val}")
                    if ok:
                        gpu_uuid = uuid_val
                except Exception as e:
                    bt.logging.debug(f"[{hotkey[:8]}] SSH probe failed - {e}")

            api_uuid = best_inst.primary_gpu_uuid if best_inst else None
            uuid_match = (
                gpu_uuid is not None
                and best_inst is not None
                and api_uuid is not None
                and gpu_uuid == api_uuid
            )
            # Detailed UUID comparison logging
            if not uuid_match and (gpu_uuid or api_uuid):
                bt.logging.debug(
                    f"[{hotkey[:8]}] UUID mismatch: ssh={gpu_uuid} vs api={api_uuid}"
                )
            bt.logging.debug(f"[{hotkey[:8]}] uuid_match={uuid_match}, api_status={api_status}")

            base_pass = allocation_ok and api_status == "pass" and uuid_match
            health_ok = None
            if base_pass and miner_info:
                try:
                    health_ok = perform_health_check(axon, miner_info, self.ssh_private_key)
                    bt.logging.debug(f"[{hotkey[:8]}] health_check={health_ok}")
                except Exception as e:
                    bt.logging.debug(f"[{hotkey[:8]}] health_check error: {e}")
                    health_ok = False

            passed = base_pass and (health_ok is not False)

            if api_status == "pass":
                base_score = 1.0 if passed else 0.0
            elif api_status == "pending":
                base_score = 1.0 if (allocation_ok and uuid_match) else 0.0
            else:
                base_score = 0.0
            bt.logging.debug(f"[{hotkey[:8]}] passed={passed}, base_score={base_score}")
        finally:
            # Always deallocate if allocation succeeded, regardless of SSH/validation outcome
            if allocation_ok:
                try:
                    await self.deallocate_miner(axon, public_key, dendrite)
                    bt.logging.debug(f"[{hotkey[:8]}] deallocation completed")
                except Exception as e:
                    bt.logging.debug(f"[{hotkey[:8]}] deallocation failed - {e}")

        if gpu_count == 0 and best_inst is not None:
            gpu_count = api_gpu_count
        if gpu_name is None and best_inst is not None:
            gpu_name = api_gpu_name

        return {
            "hotkey": hotkey,
            "allocation_ok": allocation_ok,
            "api_status": api_status,
            "alloc_state": alloc_state,
            "uuid_match": uuid_match,
            "gpu_uuid": gpu_uuid,
            "gpu_name": gpu_name,
            "gpu_count": gpu_count,
            "passed": passed,
            "health_ok": health_ok,
            "base_score": float(base_score),
        }

    async def proof_of_gpu(self):
        """
        PoG3 validation flow:
        1) Allocate a short-lived test container and read GPU UUID over SSH.
           Test containers use separate SSH port (4445) and per-validator naming,
           so all validators can verify GPU UUID regardless of production allocation state.
        2) Compare SSH UUID to API UUID; score pass/pending only when UUID matches (health check gates pass).
        GPU specs persisted to DB are API-authoritative; SSH is only used for UUID verification.
        """
        bt.logging.debug("PoG3 task execution started")
        try:
            # Refresh queryable miners
            self._queryable_uids = self.get_queryable()

            api_instances, inst_source = self.api_client.fetch_instances_full_with_meta(
                statuses=["pass", "pending", "fail", "stale", "offline", "waiting"]
            )

            if inst_source == "none" or api_instances is None:
                bt.logging.warning(
                    "PoG3 skipped: validation API unavailable or returned invalid data."
                )
                return

            if inst_source == "cache":
                bt.logging.warning(
                    "PoG3 skipped: validation API returned stale cached data. "
                    "Scoring requires live API data to ensure accuracy."
                )
                return

            api_map = self._build_api_map(api_instances)

            self.results = {}
            self.stats = {}
            bt.logging.info(f"💻 Starting PoG3 validation for {len(self._queryable_uids)} miners")

            # Run PoG3 checks in parallel batches with a single shared dendrite
            batch_size = self.config.get("pog", {}).get("batch_size", 64)
            items = list(self._queryable_uids.items())
            total_batches = (len(items) + batch_size - 1) // batch_size

            # Create single dendrite instance for all batch validations
            async with bt.dendrite(wallet=self.wallet) as dendrite:
                for i in range(0, len(items), batch_size):
                    batch = items[i:i + batch_size]
                    batch_num = i // batch_size + 1
                    bt.logging.debug(f"Validating batch {batch_num}/{total_batches}: {len(batch)} miners")

                    batch_start = time.time()
                    tasks = [self._validate_with_uid(uid, axon, api_map, dendrite) for uid, axon in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    batch_elapsed = time.time() - batch_start

                    batch_ok = 0
                    batch_fail = 0
                    for result in batch_results:
                        if isinstance(result, Exception):
                            bt.logging.debug(f"Validation exception: {result}")
                            batch_fail += 1
                            continue
                        uid, hotkey, res = result
                        self.results[hotkey] = res
                        if res and res.get("base_score", 0) > 0:
                            batch_ok += 1
                        else:
                            batch_fail += 1

                    bt.logging.debug(f"Batch {batch_num} done in {batch_elapsed:.1f}s: {batch_ok} passed, {batch_fail} failed")

            # Persist per-miner GPU specs + GPU-scaled PoG3 scores.
            for uid in self.uids:
                hotkey = self.metagraph.axons[uid].hotkey
                res = self.results.get(hotkey)
                gpu_specs = None
                base_score = 0.0
                allocated_flag = False

                if res:
                    # Allocation state from API (authoritative rental state)
                    alloc_state = res.get("alloc_state")
                    allocated_flag = self._is_allocated_state(alloc_state)

                    base_score = float(res.get("base_score") or 0.0)

                    # GPU specs are API-authoritative; SSH is only used for UUID matching.
                    if res.get("gpu_name"):
                        gpu_specs = {
                            "gpu_name": res.get("gpu_name"),
                            "num_gpus": res.get("gpu_count", 0),
                        }
                        update_pog_stats(
                            self.db,
                            hotkey,
                            gpu_specs.get("gpu_name"),
                            gpu_specs.get("num_gpus"),
                        )
                    else:
                        # No API GPU data from PoG3 attempt - purge any stale pog_stats entry
                        purge_pog_stats(self.db, hotkey)
                else:
                    # No PoG3 result for this hotkey in this run → purge any stale pog_stats entry
                    purge_pog_stats(self.db, hotkey)

                # Store GPU-scaled PoG3 score; reliability will be applied in sync_scores().
                # This makes more GPUs receive proportionally higher weights within a GPU group.
                gpu_multiplier = 0
                if isinstance(gpu_specs, dict):
                    try:
                        gpu_multiplier = int(gpu_specs.get("num_gpus") or 0)
                    except Exception:
                        gpu_multiplier = 0
                if gpu_multiplier < 0:
                    gpu_multiplier = 0

                # If miner passes validation (base_score > 0) but has missing GPU count,
                # use 1 as minimum to avoid zeroing out valid miners due to missing API data
                if base_score > 0 and gpu_multiplier == 0:
                    bt.logging.warning(f"UID {uid} passed validation but has missing GPU count, using 1 as fallback")
                    gpu_multiplier = 1

                final_score = float(base_score) * float(gpu_multiplier)

                self.stats[uid] = {
                    "hotkey": hotkey,
                    "allocated": allocated_flag,
                    "own_score": True,
                    "score": final_score * 100.0,
                    "gpu_specs": gpu_specs,
                    "reliability_score": 1.0,
                }
                self.scores[uid] = final_score

            write_stats(self.db, self.stats)

            # Build summary of successful validations
            passed_count = 0
            failed_count = 0
            summary_lines = []
            for uid in self.uids:
                hotkey = self.metagraph.axons[uid].hotkey
                res = self.results.get(hotkey)
                if res and res.get("base_score", 0) > 0:
                    passed_count += 1
                    gpu_name = res.get("gpu_name") or "unknown"
                    gpu_count = res.get("gpu_count") or 0
                    summary_lines.append(f"  UID {uid}: {gpu_count}x {gpu_name}")
                elif res:
                    failed_count += 1

            bt.logging.success(f"PoG3 completed: {passed_count} passed, {failed_count} failed")
            # Per-miner details at DEBUG level only
            for line in summary_lines:
                bt.logging.debug(line)

        except asyncio.CancelledError:
            bt.logging.info("PoG3 task cancelled (likely due to shutdown)")
        except Exception as e:
            bt.logging.error(f"Exception in proof_of_gpu: {e}\n{traceback.format_exc()}")

    def on_gpu_task_done(self, task):
        try:
            _ = task.result()
            bt.logging.debug("Proof-of-GPU task completed.")
        except Exception as e:
            bt.logging.error(f"Proof-of-GPU task failed: {e}")
        finally:
            self.gpu_task = None

    async def _publish_pog_result_event(
        self, *args, **kwargs,
    ):
        return None

    async def test_miner_gpu(self, axon, config_data):
        return (axon.hotkey, None, 0)

    async def allocate_miner(
        self,
        axon: bt.AxonInfo,
        private_key: str,
        public_key: str,
        ssh_public_key: str,
        dendrite,
    ) -> dict | None:
        """
        Ask the allocator on ``axon`` for one container and return SSH creds.

        • No preliminary "checking=True" probe – we directly request the slot.
        • Retries up to 2× on transient disconnects with 1s back-off.
        • Returns *None* if the miner is busy/declined or all retries fail.
        """
        device_requirement = {
            "cpu":       {"count": 1},
            "gpu":       {"count": 1, "capacity": 0, "type": ""},
            "hard_disk": {"capacity": 1_073_741_824},   # 1 GiB
            "ram":       {"capacity": 1_073_741_824},   # 1 GiB
            "testing":   True,
        }
        docker_requirement = {
            "base_image": "pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime",
            "ssh_key": ssh_public_key,
        }

        for attempt in range(1, self._allocation_max_retries + 1):
            try:
                # Use shared dendrite instance (passed from proof_of_gpu)
                rsp = await dendrite(
                    axon,
                    Allocate(
                        timeline=1,                    # one-shot job
                        device_requirement=device_requirement,
                        checking=False,            # real allocation
                        public_key=public_key,
                        docker_requirement=docker_requirement,
                    ),
                    timeout=self._allocation_timeout_sec,
                )

                if rsp and rsp.get("status", False):
                    # ---- decode allocator's reply -----------------------
                    try:
                        info_raw = rsp["info"]
                        if private_key:
                            # Old path: decrypt RSA encrypted response
                            dec = rsa.decrypt_data(
                                private_key.encode(),
                                base64.b64decode(info_raw),
                            )
                            info = json.loads(dec)
                        else:
                            # New path: plain JSON (base64 encoded)
                            info = json.loads(base64.b64decode(info_raw))

                        miner_info = {
                            'host': axon.ip,
                            'port': info['port'],
                            'username': info['username'],
                            'external_user_ports': info.get('external_user_ports', {}),
                        }
                        await self.pubsub_client.publish_miner_allocation(
                            miner_hotkey=axon.hotkey,
                            allocation_result=True,
                        )
                        return miner_info
                    except Exception as decode_err:
                        bt.logging.warning(f"[{axon.hotkey[:8]}] allocation decode failed: {decode_err}")
                        await self.pubsub_client.publish_miner_allocation(
                            miner_hotkey=axon.hotkey,
                            allocation_result=False,
                            allocation_error=f'Failed to decode allocation response: {decode_err}',
                        )
                        return None

                # allocator politely said "busy" or returned invalid status
                else:
                    if not rsp:
                        bt.logging.debug(f"[{axon.hotkey[:8]}] No response received for allocation")
                    else:
                        bt.logging.debug(f"[{axon.hotkey[:8]}] allocation rejected: {rsp.get('message', 'no message')}")

                    await self.pubsub_client.publish_miner_allocation(
                        miner_hotkey=axon.hotkey,
                        allocation_result=False,
                        allocation_error=(
                            'No response received'
                            if not rsp
                            else 'Miner allocation request failed'
                        ),
                    )
                    return None

            # -------- transient disconnects / 503 ------------------------------
            except ConnectionRefusedError as e:
                bt.logging.warning(
                    f"{axon.hotkey}: connection refused "
                    f"(attempt {attempt}/{self._allocation_max_retries}) – {e}"
                )
                await self.pubsub_client.publish_miner_allocation(
                    miner_hotkey=axon.hotkey,
                    allocation_result=False,
                    allocation_error="Connection refused during miner allocation",
                )
            # -------- any other error → give up immediately --------------------
            except Exception as e:
                bt.logging.trace(f"{axon.hotkey}: allocation exception – {e}")
                await self.pubsub_client.publish_miner_allocation(
                    miner_hotkey=axon.hotkey,
                    allocation_result=False,
                    allocation_error=f'Miner allocation failed: {str(e)}'
                )
                return None

            # back-off before next retry for transient errors
            if attempt < self._allocation_max_retries:
                await asyncio.sleep(self._retry_backoff_sec * attempt)

        # all retries exhausted
        await self.pubsub_client.publish_miner_allocation(
            miner_hotkey=axon.hotkey,
            allocation_result=False,
            allocation_error="All retries exhausted",
        )
        return None

    async def deallocate_miner(self, axon, public_key, dendrite):
        """
        Deallocate a miner by sending a deregistration query.

        :param axon: Axon object containing miner details.
        :param public_key: Public key of the miner; if None, it will be retrieved from the database.
        :param dendrite: Shared dendrite instance for making requests.
        """
        deallocation_error = None

        if not public_key:
            try:
                # Instantiate the connection to the database and retrieve miner details
                db = ComputeDb()
                cursor = db.get_cursor()

                cursor.execute(
                    "SELECT details, hotkey FROM allocation WHERE hotkey = ?",
                    (axon.hotkey,)
                )
                row = cursor.fetchone()

                if row:
                    info = json.loads(row[0])  # Parse JSON string from the 'details' column
                    public_key = info.get("regkey") or ""
            except Exception as e:
                deallocation_error = str(e)
                bt.logging.trace(f"{axon.hotkey}: Missing public key: {e}")

        try:
            retry_count = 0
            allocation_status = True

            while allocation_status and retry_count < self._deallocation_max_retries:
                try:
                    # Use shared dendrite instance (passed from proof_of_gpu)
                    # Must send full device_requirement dict - minimal dicts don't serialize properly
                    deregister_response = await dendrite(
                        axon,
                        Allocate(
                            timeline=0,
                            device_requirement={
                                "cpu": {"count": 1},
                                "gpu": {"count": 1, "capacity": 0, "type": ""},
                                "hard_disk": {"capacity": 1_073_741_824},
                                "ram": {"capacity": 1_073_741_824},
                                "testing": True,
                            },
                            checking=False,
                            public_key=public_key,
                        ),
                        timeout=self._deallocation_timeout_sec,
                    )

                    if deregister_response and deregister_response.get("status") is True:
                        allocation_status = False
                        bt.logging.trace(f"Deallocated miner {axon.hotkey}")
                    else:
                        retry_count += 1
                        bt.logging.trace(
                            f"{axon.hotkey}: Failed to deallocate miner. "
                            f"(attempt {retry_count}/{self._deallocation_max_retries})"
                        )
                        if retry_count >= self._deallocation_max_retries:
                            bt.logging.trace(f"{axon.hotkey}: Max retries reached for deallocating miner.")
                        await asyncio.sleep(5)
                except Exception as e:
                    retry_count += 1
                    deallocation_error = str(e)
                    bt.logging.trace(
                        f"{axon.hotkey}: Error while trying to deallocate miner. "
                        f"(attempt {retry_count}/{self._deallocation_max_retries}): {e}"
                    )
                    if retry_count >= self._deallocation_max_retries:
                        bt.logging.trace(f"{axon.hotkey}: Max retries reached for deallocating miner.")
                    await asyncio.sleep(5)
        except Exception as e:
            deallocation_error = str(e)
            bt.logging.trace(f"{axon.hotkey}: Unexpected error during deallocation: {e}")

        await self.pubsub_client.publish_miner_deallocation(
            miner_hotkey=axon.hotkey,
            retry_count=retry_count,
            deallocation_result=allocation_status is False,
            deallocation_error=deallocation_error
        )

    def get_burn_uid(self) -> int:
        """
        Returns the UID of the subnet owner (the burn account) for this subnet.
        """
        # 1) Query the on-chain SubnetOwner hotkey
        sn_owner_hotkey = self.subtensor.query_subtensor(
            "SubnetOwnerHotkey",
            params=[self.config.netuid],
        )
        bt.logging.info(f"Subnet Owner Hotkey: {sn_owner_hotkey}")

        # 2) Convert that hotkey to its UID on this subnet
        burn_uid = self.subtensor.get_uid_for_hotkey_on_subnet(
            hotkey_ss58=sn_owner_hotkey,
            netuid=self.config.netuid,
        )
        bt.logging.info(f"Subnet Owner UID (burn): {burn_uid}")
        return burn_uid

    def set_burn_weights(self):
        """
        Assigns 100% of the weight to the burn UID by clamping negatives → 0,
        L1-normalizing [1.0] into a weight, and pushing on-chain.
        """
        # 1) fetch burn UID
        burn_uid = self.get_burn_uid()

        # 2) prepare a single-element score tensor
        scores = torch.tensor([1.0], dtype=torch.float32)
        scores[scores < 0] = 0

        # 3) normalize into a weight vector that sums to 1
        weights: torch.FloatTensor = torch.nn.functional.normalize(scores, p=1.0, dim=0).float()
        bt.logging.info(f"🔥 Burn-only weight: {weights.tolist()}")

        # 4) send to chain
        result = self.subtensor.set_weights(
            netuid=self.config.netuid,
            wallet=self.wallet,
            uids=[burn_uid],
            weights=weights,
            version_key=__version_as_int__,
            wait_for_inclusion=False,
        )

        if isinstance(result, tuple) and result[0]:
            bt.logging.success("✅ Successfully set burn weights.")
        else:
            bt.logging.error(f"❌ Failed to set burn weights: {result}")

    def set_weight_capped_by_gpu(self):
        """
        Distribute emission weights to miners based on GPU type priorities (normalized),
        capped by total_miner_emission. From the non-miner remainder (1 - total_miner_emission),
        allocate treasury_emission_share to the treasury wallet (by hotkey), and burn the rest.
        """
        try:
            # Load config
            subnet_config = self.config_data.get("subnet_config", {})
            total_miner_emission = float(subnet_config.get("total_miner_emission", 0.0))
            gpu_priorities = subnet_config.get("gpu_weights", {})

            # Treasury params (prefer attributes set by load_subnet_config, fallback to config)
            treasury_wallet_hotkey = getattr(
                self, "treasury_wallet_hotkey", subnet_config.get("treasury_wallet_hotkey", "")
            )
            treasury_emission_share = float(
                getattr(self, "treasury_emission_share", subnet_config.get("treasury_emission_share", 0.0))
            )

            # Clamp emission + treasury share
            total_miner_emission   = min(max(total_miner_emission, 0.0), 1.0)
            treasury_emission_share = min(max(treasury_emission_share, 0.0), 1.0)

            # Prepare miner data
            uid_to_gpu = {}
            uid_to_score = {}
            gpu_groups = {}

            for uid in self.uids:
                if uid not in self.stats:
                    continue

                stats_entry = self.stats[uid]
                score = max(0.0, float(stats_entry.get("score", 0.0))) / 100.0

                gpu_specs = stats_entry.get("gpu_specs", {})
                if not isinstance(gpu_specs, dict):
                    continue

                gpu_name = gpu_specs.get("gpu_name", None)
                if gpu_name is None or gpu_name not in gpu_priorities:
                    continue

                priority = gpu_priorities[gpu_name]
                if priority <= 0:
                    continue

                uid_to_gpu[uid] = gpu_name
                uid_to_score[uid] = score

                if gpu_name not in gpu_groups:
                    gpu_groups[gpu_name] = []
                gpu_groups[gpu_name].append(uid)

            # Normalize GPU priorities - sum only ACTIVE GPU priorities so all miner emission is distributed
            total_priority = sum(gpu_priorities.get(gpu_name, 0) for gpu_name in gpu_groups.keys())
            if total_priority == 0:
                bt.logging.warning("⚠️ All GPU priorities are 0. Entire emission will be burned.")
                total_assigned_weight = 0.0
                uid_weights = torch.zeros(len(self.uids), dtype=torch.float32)
                gpu_actual_emission = {}
            else:
                uid_weights = torch.zeros(len(self.uids), dtype=torch.float32)
                total_assigned_weight = 0.0
                gpu_actual_emission = {}

                for gpu_name, uids in gpu_groups.items():
                    priority = gpu_priorities[gpu_name]
                    group_cap = (priority / total_priority) * total_miner_emission

                    scores = torch.tensor([uid_to_score[uid] for uid in uids], dtype=torch.float32)
                    if scores.sum() == 0:
                        continue  # no emission for this group

                    normalized = scores / scores.sum()
                    capped = normalized * group_cap

                    for i, uid in enumerate(uids):
                        idx = self.uids.index(uid)
                        uid_weights[idx] = capped[i]

                    gpu_actual_emission[gpu_name] = group_cap
                    total_assigned_weight += group_cap

            # Treasury and Burn handling
            # Non-miner remainder and treasury share from that remainder
            remainder_non_miners = max(0.0, 1.0 - total_miner_emission)
            treasury_weight = remainder_non_miners * treasury_emission_share

            # Resolve treasury UID from hotkey (if provided)
            treasury_uid = None
            if isinstance(treasury_wallet_hotkey, str) and len(treasury_wallet_hotkey) > 0:
                try:
                    treasury_uid = self.subtensor.get_uid_for_hotkey_on_subnet(
                        treasury_wallet_hotkey, self.config.netuid
                    )
                    if treasury_uid is None:
                        bt.logging.info("🏛️  Treasury hotkey not registered on subnet; treasury share will be burned.")
                    else:
                        bt.logging.info(f"🏛️  Treasury wallet: hotkey={treasury_wallet_hotkey}, uid={treasury_uid}")
                except Exception as _e:
                    bt.logging.error(f"❌ Failed to resolve treasury UID: {_e}")
                    treasury_uid = None
            else:
                if treasury_emission_share > 0.0:
                    bt.logging.info("🏛️  No treasury hotkey configured; treasury share will be burned.")

            # If treasury UID cannot be used, roll treasury share into burn
            effective_treasury_weight = treasury_weight if treasury_uid is not None else 0.0

            # Burn = (unused miner allocation) + (non-miner remainder minus treasury)
            burn_weight = max(0.0, 1.0 - total_assigned_weight - effective_treasury_weight)

            # Build final uids/weights vector with burn + (optional) treasury
            uids    = list(self.uids)
            weights = uid_weights.clone()

            # Insert/append burn weight
            burn_uid = self.get_burn_uid()
            if burn_uid in uids:
                idx = uids.index(burn_uid)
                weights[idx] = burn_weight
                bt.logging.debug("[Weights] burn_uid overwritten in-place")
            else:
                uids.append(burn_uid)
                weights = torch.cat([weights, weights.new_tensor([float(burn_weight)])])
                bt.logging.debug("[Weights] burn_uid appended")

            # Insert/append treasury weight if resolvable
            if effective_treasury_weight > 0.0 and treasury_uid is not None:
                if treasury_uid in uids:
                    idx = uids.index(treasury_uid)
                    # Add to any existing miner weight for the treasury UID
                    weights[idx] = weights[idx] + effective_treasury_weight
                    bt.logging.debug("[Weights] treasury_uid added in-place")
                else:
                    uids.append(treasury_uid)
                    weights = torch.cat([weights, weights.new_tensor([float(effective_treasury_weight)])])
                    bt.logging.debug("[Weights] treasury_uid appended")

            # final normalisation guard
            s = float(weights.sum().item())
            if s > 0:
                weights = weights / s
            else:
                # fallback: all to burn
                uids = [burn_uid]
                weights = weights.new_tensor([1.0])

            # Logging
            # Debug breakdown per GPU
            bt.logging.debug("📊 Emission breakdown per GPU group:")

            # GPU group emissions
            for gpu_name, cap in gpu_actual_emission.items():
                percent = cap * 100.0
                bt.logging.debug(f"   • {gpu_name:<25} {percent:6.2f}%")

            # Treasury & Burned portions
            treasury_percent = effective_treasury_weight * 100.0
            burn_percent     = burn_weight * 100.0

            # Totals
            bt.logging.info(f"📈 Total miner emission:       {(total_assigned_weight * 100):6.2f}%")
            bt.logging.info(f"🏛️  Treasury emission:          {treasury_percent:6.2f}%")
            bt.logging.info(f"🔥 Burned emission:            {burn_percent:6.2f}%")
            bt.logging.info(f"⚙️ Final weights: {weights.tolist()}")

            result = self.subtensor.set_weights(
                netuid=self.config.netuid,
                wallet=self.wallet,
                uids=uids,
                weights=weights,
                version_key=__version_as_int__,
                wait_for_inclusion=False,
            )

            if isinstance(result, tuple) and result[0]:
                bt.logging.success("✅ Successfully set capped GPU-based weights.")
            else:
                bt.logging.error(f"❌ Failed to set GPU-capped weights: {result}")

        except Exception as e:
            bt.logging.error(f"❌ Exception in set_weight_capped_by_gpu: {e}")

    def set_weights(self):
        # Remove all negative scores and attribute them 0.
        self.scores[self.scores < 0] = 0
        # Normalize the scores into weights
        weights: torch.FloatTensor = torch.nn.functional.normalize(self.scores, p=1.0, dim=0).float()
        bt.logging.info(f"🏋️ Weight of miners : {weights.tolist()}")
        # This is a crucial step that updates the incentive mechanism on the Bittensor blockchain.
        # Miners with higher scores (or weights) receive a larger share of TAO rewards on this subnet.
        result = self.subtensor.set_weights(
            netuid=self.config.netuid,  # Subnet to set weights on.
            wallet=self.wallet,  # Wallet to sign set weights using hotkey.
            uids=self.uids,  # Uids of the miners to set weights for.
            weights=weights,  # Weights to set for the miners.
            version_key=__version_as_int__,
            wait_for_inclusion=False,
        ) # return type: tuple[bool, str]
        if isinstance(result, tuple) and result and isinstance(result[0], bool) and result[0]:
            bt.logging.info(result)
            bt.logging.success("✅ Successfully set weights.")
        else:
            bt.logging.error(result)
            bt.logging.error("❌ Failed to set weights.")

    def next_info(self, cond, next_block):
        if cond:
            return calculate_next_block_time(self.current_block, next_block)
        else:
            return None

    def current_epoch(self, blk: int | None = None) -> int:
        return (blk or self.current_block) // self.blocks_per_epoch

    def epoch_is_pog(self, ep: int | None = None) -> bool:
        return (ep if ep is not None else self.current_epoch()) % 2 == 0

    def epoch_start_block(self, ep: int | None = None) -> int:
        e = ep if ep is not None else self.current_epoch()
        return e * self.blocks_per_epoch

    async def start(self):
        """The Main Validation Loop"""
        self.loop = asyncio.get_running_loop()

        # Step 5: Perform queries to miners, scoring, and weight
        block_next_pog = self.current_block + 1
        block_next_sync_status = 1
        block_next_set_weights = self.current_block + weights_rate_limit
        block_next_hardware_info = 1
        block_next_miner_checking = 1
        block_next_allocation_sync = self.current_block + 1  # Allocation sync on first block

        time_next_sync_status = None
        time_next_set_weights = None
        time_next_hardware_info = None
        time_next_pog = None

        bt.logging.info("Starting validator loop.")

        # Instant validation: launch PoG immediately on first startup
        self._instant_started = getattr(self, "_instant_started", False)
        if self.instant_validation and not self._instant_started:
            bt.logging.info("⚡ Instant validation enabled: launching PoG immediately.")
            if self.gpu_task is None or self.gpu_task.done():
                self.gpu_task = asyncio.create_task(self.proof_of_gpu())
                self.gpu_task.add_done_callback(self.on_gpu_task_done)
            self._instant_started = True

        while True:
            try:
                self.sync_local()
                self.refresh_config_from_server()

                hk_obj = self.wallet.hotkey
                my_hk  = getattr(hk_obj, "ss58_address", None) or str(hk_obj)

                if self.current_block not in self.blocks_done:
                    self.blocks_done.add(self.current_block)

                    time_next_sync_status = self.next_info(not block_next_sync_status == 1, block_next_sync_status)
                    time_next_set_weights = self.next_info(not block_next_set_weights == 1, block_next_set_weights)
                    time_next_hardware_info = self.next_info(
                        not block_next_hardware_info == 1 and self.validator_perform_hardware_query, block_next_hardware_info
                    )
                    time_next_pog = self.next_info(not block_next_pog == 1, block_next_pog)

                    # Schedule PoG3 on block cadence.
                    if self.current_block >= block_next_pog:
                        if self.gpu_task is None or self.gpu_task.done():
                            bt.logging.info(f"🚀 Scheduling PoG3 at block {self.current_block}")
                            self.gpu_task = asyncio.create_task(self.proof_of_gpu())
                            self.gpu_task.add_done_callback(self.on_gpu_task_done)
                        else:
                            bt.logging.debug("PoG3 deferred: previous task still running")
                        block_next_pog = self.current_block + self.pog_interval_blocks
                        time_next_pog = calculate_next_block_time(self.current_block, block_next_pog)

                    # Perform specs queries
                    if (self.current_block % block_next_hardware_info == 0 and self.validator_perform_hardware_query) or (
                        block_next_hardware_info < self.current_block and self.validator_perform_hardware_query
                    ):
                        block_next_hardware_info = self.current_block + self._block_interval_hardware_info

                        if not hasattr(self, "_queryable_uids"):
                            self._queryable_uids = self.get_queryable()

                        # self.loop.run_in_executor(None, self.execute_specs_request) replaced by wandb query.
                        await self.get_specs_wandb()

                    # Perform miner checking
                    if self.current_block % block_next_miner_checking == 0 or block_next_miner_checking < self.current_block:
                        # Next block the validators will do port checking again.
                        block_next_miner_checking = self.current_block + self._block_interval_miner_check

                        # Filter axons with stake and ip address.
                        self._queryable_uids = self.get_queryable()

                        # self.sync_checklist()

                    if self.current_block % block_next_sync_status == 0 or block_next_sync_status < self.current_block:
                        block_next_sync_status = self.current_block + self._block_interval_sync_status
                        self.sync_status()
                        # Log chain data to wandb
                        chain_data = {
                            "Block": self.current_block,
                            "Stake": self._safe_get_metric(self.metagraph.S),
                            "Rank": self._safe_get_metric(self.metagraph.R),
                            "vTrust": self._safe_get_metric(self.metagraph.validator_trust),
                            "Emission": self._safe_get_metric(self.metagraph.E),
                        }
                        self.wandb.log_chain_data(chain_data)

                    # Sync allocation status to validation API (every block)
                    if self.current_block >= block_next_allocation_sync:
                        await self.sync_allocation_status_to_api()
                        block_next_allocation_sync = self.current_block + 1

                    # Periodically update the weights on the Bittensor blockchain, ~ every 20 minutes
                    if self.current_block - self.last_updated_block > weights_rate_limit:
                        block_next_set_weights = self.current_block + weights_rate_limit
                        self.sync_scores()
                        self.set_weight_capped_by_gpu()
                        self.last_updated_block = self.current_block
                        self.blocks_done.clear()
                        self.blocks_done.add(self.current_block)

                    # Refresh tokens periodically
                    if self.current_block % self._block_interval_token_refresh == 0:
                        bt.logging.info("Refreshing SN27 token gateway tokens")
                        self.pubsub_client.refresh_credentials()

                # Per-block summary log
                bt.logging.info(
                    (
                        f"Block:{self.current_block} | "
                        f"Stake:{self._safe_get_metric(self.metagraph.S)} | "
                        f"Rank:{self._safe_get_metric(self.metagraph.R)} | "
                        f"vTrust:{self._safe_get_metric(self.metagraph.validator_trust)} | "
                        f"Emission:{self._safe_get_metric(self.metagraph.E)} | "
                        f"next_PoG:    #{block_next_pog} ~ {time_next_pog} | "
                        f"sync_status:   #{block_next_sync_status} ~ {time_next_sync_status} | "
                        f"set_weights:   #{block_next_set_weights} ~ {time_next_set_weights} | "
                    )
                )

                await asyncio.sleep(1)

            # If we encounter an unexpected error, log it for debugging.
            except RuntimeError as e:
                bt.logging.error(e)
                traceback.print_exc()

            # If the user interrupts the program, gracefully exit.
            except KeyboardInterrupt:
                self.db.close()
                bt.logging.success("Keyboard interrupt detected. Exiting validator.")
                exit()

async def _main():
    validator = Validator()
    await asyncio.gather(
        validator.start(),
        validator.pubsub_client.subscribe_to_topics(),
    )


def main():
    """
    Main function to run the neuron.

    This function initializes and runs the neuron. It handles the main loop, state management, and interaction
    with the Bittensor network.
    """
    asyncio.run(_main())


if __name__ == "__main__":
    main()
