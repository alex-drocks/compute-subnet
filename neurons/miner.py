# The MIT License (MIT)
# Copyright © 2023 GitPhantomman
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

# Ensure project root is in sys.path so local modules are found regardless of cwd
import sys
from pathlib import Path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import asyncio
import json
import os
import threading
import time
import traceback
import typing
import multiprocessing
import base64
import yaml
import bittensor as bt
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Filter out noisy error messages from bittensor axon
import logging
class _AxonErrorFilter(logging.Filter):
    def filter(self, record):
        msg = str(record.msg)
        # Suppress UnknownSynapseError with empty synapse name (probe requests)
        if "UnknownSynapseError" in msg and "Synapse name ''" in msg:
            return False
        # Suppress BlacklistedException for validators without enough stake
        if "BlacklistedException" in msg and "Not enough stake" in msg:
            return False
        return True

# Apply filter to bittensor's logger
logging.getLogger("bittensor").addFilter(_AxonErrorFilter())

from compute import (
    SUSPECTED_EXPLOITERS_HOTKEYS,
    __version_as_int__,
    validator_permit_stake,
    miner_priority_allocate,
    TRUSTED_VALIDATORS_HOTKEYS,
)
from compute.axon import ComputeSubnetAxon, ComputeSubnetSubtensor
from compute.protocol import Allocate
from compute.utils.math import percent
from compute.utils.exceptions import make_error_response
from compute.utils.parser import ComputeArgPaser
from compute.utils.socket import check_port
from compute.utils.subtensor import (
    is_registered,
    get_current_block,
    calculate_next_block_time,
    RegistrationStatus,
)
from compute.utils.version import (
    try_update,
    version2number,
    get_remote_version,
)
from neurons.Miner.allocate import (
    check_allocation,
    register_allocation,
    deregister_allocation,
    check_if_allocated,
)
from neurons.Miner.container import (
    create_check_container,
    pull_default_image,
    pull_custom_template_images,
    check_container,
    kill_container,
    restart_container,
    exchange_key_container,
    pause_container,
    unpause_container,
    pull_image,
    DEFAULT_TEST_SSH_PORT,
)
from compute.wandb.wandb import ComputeWandb
from neurons.Miner.allocate import check_allocation, register_allocation
from neurons.Miner.http_server import start_server, stop_server
from neurons.Miner.pow import check_cuda_availability

# from neurons.Miner.specs import RequestSpecsProcessor
from neurons.Validator.script import check_docker_availability
from neurons.Validator.api_client import ValidationApiClient
from neurons.Miner import pog
from socketserver import TCPServer


class Miner:
    blocks_done: set = set()

    blacklist_hotkeys: set
    blacklist_coldkeys: set
    whitelist_hotkeys: set
    whitelist_coldkeys: set
    whitelist_hotkeys_version: set = set()
    exploiters_hotkeys_set: set

    miner_whitelist_updated_threshold: int

    miner_subnet_uid: typing.Optional[int] = None

    miner_http_server: TCPServer

    _axon: bt.axon

    # Off-chain mode tracking
    _is_offchain: bool = False
    _offchain_entry: typing.Optional[dict] = None

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
    def axon(self) -> bt.axon:
        return self._axon

    @property
    def current_block(self):
        return get_current_block(subtensor=self.subtensor)

    def __init__(self):
        # Step 1: Parse the bittensor and compute subnet config
        self.config = self.init_config()

        # Setup extra args
        self.miner_whitelist_updated_threshold = (
            self.config.miner_whitelist_updated_threshold
        )
        self.miner_whitelist_not_enough_stake = (
            self.config.miner_whitelist_not_enough_stake
        )
        self.init_black_and_white_list()

        # Set up logging with the provided configuration and directory.
        bt.logging(config=self.config, logging_dir=self.config.full_path)
        bt.logging.info(
            f"Running miner for subnet: {self.config.netuid} on network: {self.config.subtensor.chain_endpoint} with config:"
        )
        # Log the configuration for reference.
        bt.logging.info(self.config)

        # Step 2: Build Bittensor miner objects
        # These classes are vital to interact and function within the Bittensor network.
        bt.logging.info("Setting up bittensor objects.")

        # Wallet holds cryptographic information, ensuring secure transactions and communication.
        self._wallet = bt.wallet(config=self.config)
        bt.logging.info(f"Wallet: {self.wallet}")

        self.api_client = ValidationApiClient(self.wallet)

        # Subtensor manages the blockchain connection, facilitating interaction with the Bittensor blockchain.
        self._subtensor = ComputeSubnetSubtensor(config=self.config)
        bt.logging.info(f"Subtensor: {self.subtensor}")

        # Metagraph provides the network's current state, holding state about other participants in a subnet.
        self._metagraph = self.subtensor.metagraph(self.config.netuid)
        bt.logging.info(f"Metagraph: {self.metagraph}")

        # Build sample container image to speed up the allocation process
        pull_default_image()
        # Pull all custom template images to avoid timeouts during allocation
        pull_custom_template_images()
        create_check_container()
        has_docker, msg = check_docker_availability()

        if not has_docker:
            bt.logging.error(msg)
            exit(1)
        else:
            bt.logging.info(f"Docker is installed. Version: {msg}")

        check_cuda_availability()

        self.uids: list = self.metagraph.uids.tolist()

        self.sync_status()
        self.init_axon()

        # Step 4: Initialize wandb
        self.wandb = ComputeWandb(self.config, self.wallet, os.path.basename(__file__))
        self.wandb.update_specs()

        # check allocation status
        self.allocation_status = False
        self._last_allocation_ts: float = 0.0  # Track time of last successful allocation (for grace period)
        self.__check_alloaction_errors()

        self.last_updated_block = self.current_block - (self.current_block % 100)
        self.allocate_lock = threading.Lock()
        # Launch the PoG3 proof runner in the background
        self.start_pog3_runner()

    @staticmethod
    def _is_allocated_state(state: typing.Optional[str]) -> bool:
        return isinstance(state, str) and state.lower() == "allocated"

    def _read_pog_alloc_state(self, max_age: float = 60.0) -> typing.Optional[str]:
        """Read allocation state from PoG shared file if fresh. Returns None if unavailable."""
        state_file = Path.home() / ".miner_validator" / "alloc_state.json"
        try:
            data = json.loads(state_file.read_text())
            if data.get("hotkey") == self.wallet.hotkey.ss58_address:
                age = time.time() - data.get("ts", 0)
                if age < max_age:
                    return data.get("alloc_state")
        except Exception:
            pass
        return None

    def _fetch_alloc_state(self) -> typing.Tuple[bool, typing.Optional[str]]:
        """Returns (success, alloc_state). Uses PoG file first, falls back to API."""
        # Try PoG shared file first
        state = self._read_pog_alloc_state()
        if state is not None:
            bt.logging.debug(f"Using PoG allocation state: {state}")
            return (True, state)

        # Fall back to API
        try:
            data = self.api_client.fetch_allocation_status(self.wallet.hotkey.ss58_address)
        except Exception as e:
            bt.logging.warning(f"Allocation status check failed: {e}")
            return (False, None)

        if isinstance(data, dict):
            state = data.get("alloc_state") or data.get("allocation_state") or data.get("state")
            if state is not None:
                return (True, str(state))
            # API returned valid response but no allocation state - treat as failure
            bt.logging.warning("Allocation API response missing alloc_state; treating as failure")
            return (False, None)

        # API returned None or invalid response - treat as failure
        bt.logging.warning("Allocation API returned invalid response; treating as failure")
        return (False, None)

    def _sync_allocation_status(self) -> None:
        """Update allocation_status from PoG file if available (lightweight, no API call)."""
        state = self._read_pog_alloc_state()
        if state is not None:
            self.allocation_status = self._is_allocated_state(state)

    def __check_alloaction_errors(self):
        # Read allocation grace period directly from config.yaml
        # DO NOT import from pog.config here - it pollutes the child's sys.modules
        # when forking the PoG subprocess, causing it to use stale wallet config
        try:
            cfg = yaml.safe_load(open("config.yaml")) or {}
            grace_sec = float(cfg.get("pog", {}).get("allocation_grace_sec", 120.0))
        except Exception as e:
            bt.logging.debug(f"Could not read config.yaml for grace_sec: {e}, using default 120.0")
            grace_sec = 120.0

        # kill running containers when they are not supposed to run
        file_path = "allocation_key"
        allocation_key_encoded = None

        # Grace period: don't trust external state during grace period after allocation
        # This prevents race condition where API hasn't synced allocation status yet
        elapsed = time.time() - self._last_allocation_ts
        if elapsed < grace_sec:
            remaining = grace_sec - elapsed
            bt.logging.debug(f"Skipping cleanup: within allocation grace period ({remaining:.0f}s remaining)")
            return

        api_success, alloc_state = self._fetch_alloc_state()
        if api_success:
            # API responded - use the state (None = free)
            prev_status = self.allocation_status
            self.allocation_status = self._is_allocated_state(alloc_state)
            if prev_status != self.allocation_status:
                bt.logging.info(f"Allocation status changed: {prev_status} → {self.allocation_status}")
        else:
            # API offline - keep previous status, skip cleanup
            bt.logging.warning("Allocation API unavailable; skipping allocation cleanup.")

        if os.path.exists(file_path):
            # Open the file in read mode ('r') and read the data
            with open(file_path, "r") as file:
                allocation_key_encoded = file.read()

            if (
                api_success
                and not self.allocation_status
                and allocation_key_encoded
            ):
                # wandb says not allocated but leftovers found, let's deallocate
                # Decode the base64-encoded public key from the file
                public_key = base64.b64decode(allocation_key_encoded).decode("utf-8")
                deregister_allocation(public_key)
                bt.logging.info(
                    "Allocation is not active per API. Resetting the allocation status."
                )

            if check_container() and not allocation_key_encoded:
                # no allocation key yet running container, let's remove it
                # force_kill_prod=True: kill prod container without key verification (orphan cleanup)
                # kill_test=False: don't kill test containers as they are used by validators
                # for allocation capability checks
                try:
                    kill_container(force_kill_prod=True, kill_test=False)
                except Exception as e:
                    bt.logging.warning(f"Error killing container: {e}")

                bt.logging.info("Container running without active allocation. Killing orphan container.")

    def _load_attestation_layer_settings(self) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
        """
        Resolve Attestation Layer URL/token from env (preferred) with config.yaml fallback.
        """
        url = os.getenv("ATTESTATION_LAYER_URL")
        token = os.getenv("ATTESTATION_LAYER_AUTH_TOKEN")

        if url and token:
            return url, token

        try:
            data = yaml.safe_load(open("config.yaml", "r"))
            al_cfg = data.get("attestation_layer", {}) if isinstance(data, dict) else {}
            if not url:
                host = os.getenv("ATTESTATION_LAYER_HOST") or al_cfg.get("host", "127.0.0.1")
                port = os.getenv("ATTESTATION_LAYER_PORT") or al_cfg.get("port", 8080)
                try:
                    port = int(port)
                except Exception:
                    port = 8080
                base_path = os.getenv("ATTESTATION_LAYER_BASE_PATH") or al_cfg.get("base_path", "/v1") or "/v1"
                base_path = base_path if str(base_path).startswith("/") else f"/{base_path}"
                explicit = al_cfg.get("url")
                url = (explicit or f"http://{host}:{port}{base_path}").rstrip("/")
            if not token:
                token = al_cfg.get("auth_token") or None
        except Exception as e:
            bt.logging.debug(f"Could not read config.yaml for attestation layer config: {e}")
        return url, token

    def _build_pog3_env(self) -> dict:
        env = os.environ.copy()
        # Use direct assignment so CLI args always take precedence over env vars
        wallet_name = getattr(self.config.wallet, "name", None)
        hotkey_name = getattr(self.config.wallet, "hotkey", None)
        if wallet_name:
            env["MINER_WALLET_NAME"] = str(wallet_name)
        if hotkey_name:
            env["MINER_HOTKEY_NAME"] = str(hotkey_name)

        axon_ip = getattr(self.config.axon, "external_ip", None) or getattr(self.config.axon, "ip", None)
        axon_port = getattr(self.config.axon, "port", None)
        if axon_ip:
            env.setdefault("MINER_AXON_HOST", str(axon_ip))
        if axon_port:
            env.setdefault("MINER_AXON_PORT", str(axon_port))

        # SSH port: prioritize CLI arg (--ssh.port), fallback to .env MINER_SSH_PORT, default 4444
        ssh_port = getattr(self.config.ssh, "port", None)
        if ssh_port:
            env.setdefault("MINER_SSH_PORT", str(ssh_port))

        # Test SSH port: prioritize CLI arg (--ssh.test_port), fallback to .env MINER_TEST_SSH_PORT, default 4445
        test_ssh_port = getattr(self.config.ssh, "test_port", None)
        if test_ssh_port:
            env.setdefault("MINER_TEST_SSH_PORT", str(test_ssh_port))

        # Subtensor endpoint: prioritize CLI arg (--subtensor.chain_endpoint), fallback to .env
        chain_endpoint = getattr(self.config.subtensor, "chain_endpoint", None)
        if chain_endpoint:
            endpoint_str = str(chain_endpoint)
            if endpoint_str.startswith("wss://") or endpoint_str.startswith("ws://"):
                env["MINER_RPC_WSS"] = endpoint_str
            elif endpoint_str.startswith("http://") or endpoint_str.startswith("https://"):
                env["MINER_RPC_HTTP"] = endpoint_str
        else:
            # If no explicit endpoint, derive from network name
            network = getattr(self.config.subtensor, "network", None)
            if network == "finney":
                env.setdefault("MINER_RPC_WSS", "wss://entrypoint-finney.opentensor.ai:443")
            elif network == "test":
                env.setdefault("MINER_RPC_WSS", "wss://test.finney.opentensor.ai:443")
            elif network == "local":
                env.setdefault("MINER_RPC_WSS", "ws://127.0.0.1:9944")

        url, token = self._load_attestation_layer_settings()
        if url:
            env.setdefault("ATTESTATION_LAYER_URL", url)
        if token:
            env.setdefault("ATTESTATION_LAYER_AUTH_TOKEN", token)

        extra_path = os.path.join(os.getcwd(), "src")
        env["PYTHONPATH"] = (
            f"{extra_path}:{env.get('PYTHONPATH','')}"
            if env.get("PYTHONPATH")
            else extra_path
        )
        return env

    def start_pog3_runner(self):
        env = self._build_pog3_env()
        try:
            pog.start_pog_loop(env)
            bt.logging.info("🔄 Started PoG3 miner loop.")
        except Exception as e:
            bt.logging.error(f"Failed to launch PoG3 miner loop: {e}")

    def stop_pog3_runner(self):
        try:
            pog.stop_pog_loop()
        except Exception:
            pass

    def init_axon(self):
        # Step 6: Build and link miner functions to the axon.
        # The axon handles request processing, allowing validators to send this process requests.
        self._axon = ComputeSubnetAxon(wallet=self.wallet, config=self.config)

        self.axon.attach(
            forward_fn=self.allocate,
            blacklist_fn=self.blacklist_allocate,
            priority_fn=self.priority_allocate,
        )

        if self._is_offchain:
            # Off-chain mode: start axon without serving to chain
            bt.logging.info(
                f"OFF-CHAIN mode: Starting axon on port {self.config.axon.port} "
                f"(not serving to chain)"
            )
            self.axon.start()
        else:
            # On-chain mode: full serve + start
            # Serve passes the axon information to the network + netuid we are hosting on.
            # This will auto-update if the axon port of external ip have changed.
            bt.logging.info(
                f"Serving axon {self.axon} on network: {self.config.subtensor.chain_endpoint} with netuid: {self.config.netuid}"
            )
            self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor)

            # Start  starts the miner's axon, making it active on the network.
            bt.logging.info(f"Starting axon server on port: {self.config.axon.port}")
            self.axon.start()

    @staticmethod
    def init_config():
        """
        This function is responsible for setting up and parsing command-line arguments.
        :return: config
        """
        parser = ComputeArgPaser(
            description="This script aims to help miners with the compute subnet."
        )
        config = bt.config(parser)

        # Step 3: Set up logging directory
        # Logging captures events for diagnosis or understanding miner's behavior.
        config.full_path = os.path.expanduser(
            "{}/{}/{}/netuid{}/{}".format(
                config.logging.logging_dir,
                config.wallet.name,
                config.wallet.hotkey,
                config.netuid,
                "miner",
            )
        )

        # Ensure the directory for logging exists, else create one.
        if not os.path.exists(config.full_path):
            os.makedirs(config.full_path, exist_ok=True)
        return config

    def init_black_and_white_list(self):
        default_whitelist = self.config.whitelist_hotkeys + TRUSTED_VALIDATORS_HOTKEYS

        # Set blacklist and whitelist arrays
        self.blacklist_hotkeys = {hotkey for hotkey in self.config.blacklist_hotkeys}
        self.blacklist_coldkeys = {
            coldkey for coldkey in self.config.blacklist_coldkeys
        }
        self.whitelist_hotkeys = {hotkey for hotkey in default_whitelist}
        self.whitelist_coldkeys = {
            coldkey for coldkey in self.config.whitelist_coldkeys
        }

        if self.config.blacklist_exploiters:
            self.exploiters_hotkeys_set = {key for key in SUSPECTED_EXPLOITERS_HOTKEYS}
        else:
            self.exploiters_hotkeys_set = set()

    def sync_local(self):
        """Resync our local state with the latest state from the blockchain. Sync scores with metagraph."""
        self.metagraph.sync(subtensor=self.subtensor)

    def _safe_get_metric(self, metric_array, default: float = 0.0) -> float:
        """Safely access metagraph metric for this miner's UID with bounds checking."""
        try:
            uid = self.miner_subnet_uid
            if uid is not None and 0 <= uid < len(metric_array):
                return float(metric_array[uid])
        except Exception:
            pass
        return default

    def sync_status(self):
        """
        Sync registration status. Supports both on-chain and off-chain modes.
        Returns RegistrationStatus for tracking mode changes.
        """
        reg_status = is_registered(
            wallet=self.wallet,
            metagraph=self.metagraph,
            subtensor=self.subtensor,
            entity="miner",
            allow_offchain=True,
        )

        if isinstance(reg_status, RegistrationStatus):
            old_offchain = self._is_offchain
            self._is_offchain = reg_status.is_offchain
            self._offchain_entry = reg_status.attestation_entry
            self.miner_subnet_uid = reg_status.uid

            # Log mode transitions
            if old_offchain and not self._is_offchain:
                bt.logging.success(f"Transitioned from OFF-CHAIN to ON-CHAIN mode! UID: {reg_status.uid}")
            elif not old_offchain and self._is_offchain:
                bt.logging.warning("Transitioned from ON-CHAIN to OFF-CHAIN mode")
        else:
            # Backward compatibility: int UID returned
            self.miner_subnet_uid = reg_status
            self._is_offchain = False
            self._offchain_entry = None

        # Check for auto update
        if self.config.auto_update:
            try_update()

        # Axon version check - only for on-chain miners with valid UID
        if hasattr(self, "axon") and self.axon and self.miner_subnet_uid is not None:
            try:
                subnet_axon_version: bt.AxonInfo = self.metagraph.neurons[
                    self.miner_subnet_uid
                ].axon_info
                current_version = __version_as_int__
                if subnet_axon_version.version != current_version:
                    bt.logging.info(
                        "Axon info version has been changed. Needs to restart axon..."
                    )
                    self.axon.stop()
                    self.init_axon()
            except (IndexError, AttributeError):
                # Off-chain miners won't have metagraph neuron entry
                pass

    def base_blacklist(
        self, synapse: Allocate
    ) -> typing.Tuple[bool, str]:
        hotkey = synapse.dendrite.hotkey
        synapse_type = type(synapse).__name__

        # Off-chain mode: more permissive since we can't fully verify metagraph
        if self._is_offchain:
            # Always accept whitelisted validators
            if hotkey in self.whitelist_hotkeys:
                bt.logging.trace(f"Off-chain mode: accepting whitelisted validator {hotkey[:8]}")
                return False, "Whitelisted validator (off-chain mode)"

            # Always block exploiters
            if hotkey in self.exploiters_hotkeys_set:
                return True, f"Blocked exploiter hotkey: {hotkey}"

            # Block explicitly blacklisted hotkeys
            if len(self.blacklist_hotkeys) > 0 and hotkey in self.blacklist_hotkeys:
                return True, "Blocked hotkey"

            # Accept request (off-chain mode is more permissive)
            bt.logging.trace(f"Off-chain mode: accepting request from {hotkey[:8]}")
            return False, "Accepted (off-chain mode)"

        # On-chain mode: original logic
        if hotkey not in self.metagraph.hotkeys:
            # Ignore requests from unrecognized entities.
            bt.logging.trace(f"Blacklisting unrecognized hotkey {hotkey}")
            return True, "Unrecognized hotkey"

        index = self.metagraph.hotkeys.index(hotkey)
        stake = self.metagraph.S[index].item()

        if stake < validator_permit_stake and not self.miner_whitelist_not_enough_stake:
            bt.logging.trace(f"Not enough stake {stake}")
            return True, "Not enough stake!"

        if len(self.blacklist_hotkeys) > 0 and hotkey in self.blacklist_hotkeys:
            return True, "Blocked hotkey"

        #Blacklist entities that are not up-to-date
        if hotkey not in self.whitelist_hotkeys_version and len(self.whitelist_hotkeys_version) > 0:
            bt.logging.trace(f"Blacklisted a {synapse_type} request from a non-updated hotkey: {hotkey}")
            return (
                True,
                f"Blocked an {synapse_type} request from a non-updated hotkey: {hotkey}",
            )

        if hotkey in self.exploiters_hotkeys_set:
            return (
                True,
                f"Blacklisted an {synapse_type} request from an exploiter hotkey: {hotkey}",
            )

        bt.logging.trace(
            f"Not Blacklisting recognized hotkey {synapse.dendrite.hotkey}"
        )
        return False, "Hotkey recognized!"

    def base_priority(self, synapse: Allocate) -> float:
        caller_uid = self._metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self._metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: {priority}"
        )
        return priority

    # The blacklist function decides if a request should be ignored.
    # def blacklist_specs(self, synapse: Specs) -> typing.Tuple[bool, str]:
    #    return self.base_blacklist(synapse)

    # The priority function determines the order in which requests are handled.
    # More valuable or higher-priority requests are processed before others.
    # def priority_specs(self, synapse: Specs) -> float:
    #    return self.base_priority(synapse) + miner_priority_specs

    # The blacklist function decides if a request should be ignored.
    def blacklist_allocate(self, synapse: Allocate) -> typing.Tuple[bool, str]:
        return self.base_blacklist(synapse)

    # The priority function determines the order in which requests are handled.
    # More valuable or higher-priority requests are processed before others.
    def priority_allocate(self, synapse: Allocate) -> float:
        return self.base_priority(synapse) + miner_priority_allocate

    def update_allocation(self, synapse: Allocate):
        if (
            not synapse.checking
            and isinstance(synapse.output, dict)
            and synapse.output.get("status") is True
        ):
            if synapse.timeline > 0:
                self._last_allocation_ts = time.time()  # Start grace period
                self.wandb.update_allocated(synapse.dendrite.hotkey)
                bt.logging.success(f"✅ Allocation made by {synapse.dendrite.hotkey}.")
            else:
                self._last_allocation_ts = 0.0  # Reset grace period on deallocation
                self.wandb.update_allocated(None)
                bt.logging.success(f"✅ De-allocation made by {synapse.dendrite.hotkey}.")

    # This is the Allocate function, which decides the miner's response to a valid, high-priority request.
    def allocate(self, synapse: Allocate) -> Allocate:
        timeline = synapse.timeline
        device_requirement = synapse.device_requirement
        checking = synapse.checking
        docker_requirement = synapse.docker_requirement
        docker_requirement["external_ports"] = {
            "ssh": int(self.config.ssh.port),
        }

        # Multiple ports support
        # Parse --external.ports which is a comma-separated list like "27015,27016,27017,27018"
        external_ports_str = getattr(self.config.external, 'ports', "27015,27016,27017,27018")
        external_ports_list = [int(p.strip()) for p in external_ports_str.split(",")]

        # Internal ports are fixed: 27015, 27016, 27017, 27018
        internal_ports = [27015, 27016, 27017, 27018]

        # Map internal to external ports
        external_user_ports = {}
        for i, internal_port in enumerate(internal_ports):
            if i < len(external_ports_list):
                external_user_ports[internal_port] = external_ports_list[i]

        docker_requirement["external_user_ports"] = external_user_ports

        docker_change = synapse.docker_change
        docker_action = synapse.docker_action

        if checking is True:
            if timeline > 0:  # positive means allocate, negative means deallocate (FIXME: this is weird)
                result = check_allocation(timeline, device_requirement, return_docker_info=True)
                synapse.output = result
            else:
                public_key = synapse.public_key
                result = check_if_allocated(public_key=public_key)
                synapse.output = result
        else:
            if docker_action["action"] == "pull":
                # pull image here
                result = pull_image(docker_requirement.get("image"))
                synapse.output = result
                return synapse
            if docker_change is True:
                if docker_action["action"] == "exchange_key":
                    public_key = synapse.public_key
                    new_ssh_key = docker_action["ssh_key"]
                    key_type = docker_action["key_type"]
                    result = exchange_key_container(new_ssh_key, public_key, key_type)
                    synapse.output = result
                elif docker_action["action"] == "restart":
                    public_key = synapse.public_key
                    result = restart_container(public_key)
                    synapse.output = result
                elif docker_action["action"] == "pause":
                    public_key = synapse.public_key
                    result = pause_container(public_key)
                    synapse.output = result
                elif (
                    docker_action["action"] == "unpause"
                    or docker_action["action"] == "resume"
                ):
                    public_key = synapse.public_key
                    result = unpause_container(public_key)
                    synapse.output = result
                else:
                    bt.logging.info(f"Unknown action: {docker_action['action']}")
            else:
                # actual allocation
                public_key = synapse.public_key
                validator_hotkey = synapse.dendrite.hotkey
                is_test_allocation = device_requirement.get("testing", False)

                # Get test SSH port: prioritize CLI arg (--ssh.test_port), fallback to .env, then default
                test_ssh_port = getattr(self.config.ssh, "test_port", None) or int(os.getenv("MINER_TEST_SSH_PORT", DEFAULT_TEST_SSH_PORT))

                if timeline > 0:
                    if is_test_allocation:
                        # Test allocations always allowed - per-validator containers on separate port
                        # Test containers use different SSH port (4445) and per-validator naming
                        # They do NOT interfere with production containers
                        bt.logging.info(f"Test allocation for {validator_hotkey[:8]} on port {test_ssh_port}")
                        result = register_allocation(timeline, device_requirement, public_key, docker_requirement, validator_hotkey, test_ssh_port)
                        synapse.output = result
                        synapse.output["port"] = test_ssh_port
                    else:
                        # Production allocations: use lock to ensure only one at a time
                        if self.allocate_lock.acquire(blocking=False):
                            try:
                                result = register_allocation(timeline, device_requirement, public_key, docker_requirement, validator_hotkey)
                                synapse.output = result
                                synapse.output["port"] = int(self.config.ssh.port)
                            finally:
                                self.allocate_lock.release()
                        else:
                            synapse.output = make_error_response(
                                f"Allocation is already in progress. Please wait for the previous one to finish",
                                status=False,
                            )
                else:  # timeline <= 0 (deallocate)
                    if is_test_allocation:
                        # Test deallocation: kill only this validator's test container
                        if validator_hotkey:
                            from neurons.Miner.container import kill_test_container_for_validator
                            result = kill_test_container_for_validator(validator_hotkey)
                            synapse.output = result
                        else:
                            synapse.output = make_error_response(
                                "No validator hotkey for test deallocation",
                                status=False,
                            )
                    else:
                        # Production deallocation: normal deregistration
                        result = deregister_allocation(public_key)
                        synapse.output = result
                self.update_allocation(synapse)
        return synapse

    def get_updated_validator(self):
        try:
            self.whitelist_hotkeys_version.clear()
            try:
                latest_version = version2number(
                    get_remote_version(pattern="__minimal_validator_version__")
                )

                if latest_version is None:
                    bt.logging.error(
                        f"Github API call failed or version string is incorrect!"
                    )
                    return

                valid_validators = self.get_valid_validator()

                valid_validators_version = [
                    uid
                    for uid, hotkey, version in valid_validators
                    if version >= latest_version
                ]
                if (
                    percent(len(valid_validators_version), len(valid_validators))
                    <= self.miner_whitelist_updated_threshold
                ):
                    bt.logging.info(
                        f"Less than {self.miner_whitelist_updated_threshold}% validators are currently using the last version. Allowing all."
                    )
                else:
                    mismatch_count = 0
                    for uid, hotkey, version in valid_validators:
                        try:
                            if version >= latest_version:
                                self.whitelist_hotkeys_version.add(hotkey)
                                bt.logging.trace(f"Version match: {hotkey}")
                            else:
                                mismatch_count += 1
                                bt.logging.trace(f"Version mismatch: {hotkey}")
                        except Exception:
                            bt.logging.error(
                                f"exception in get_valid_hotkeys: {traceback.format_exc()}"
                            )

                    bt.logging.info(
                        f"Validator whitelist: {len(self.whitelist_hotkeys_version)} valid, {mismatch_count} version mismatch"
                    )
            except json.JSONDecodeError:
                bt.logging.error(
                    f"exception in get_valid_hotkeys: {traceback.format_exc()}"
                )
        except Exception as _:
            bt.logging.error(traceback.format_exc())

    def get_valid_validator_uids(self):
        valid_uids = []
        uids = self.metagraph.uids.tolist()
        for index, uid in enumerate(uids):
            if self.metagraph.total_stake[index] > validator_permit_stake:
                valid_uids.append(uid)
        return valid_uids

    def get_valid_validator(self) -> typing.List[typing.Tuple[int, str, int]]:
        valid_validator_uids = self.get_valid_validator_uids()
        valid_validator = []
        for uid in valid_validator_uids:
            neuron = self.subtensor.neuron_for_uid(uid, self.config.netuid)
            hotkey = neuron.hotkey
            version = neuron.prometheus_info.version
            valid_validator.append((uid, hotkey, version))
        return valid_validator

    def get_valid_validator_hotkeys(self):
        valid_hotkeys = []
        valid_validator_uids = self.get_valid_validator_uids()
        for uid in valid_validator_uids:
            neuron = self.subtensor.neuron_for_uid(uid, self.config.netuid)
            hotkey = neuron.hotkey
            valid_hotkeys.append(hotkey)
        return valid_hotkeys

    def next_info(self, cond, next_block):
        if cond:
            return calculate_next_block_time(self.current_block, next_block)
        else:
            return None

    async def start(self):
        """The Main Validation Loop"""

        # Load miner block intervals from config.yaml
        # (loaded here, not at init, to avoid polluting sys.modules before PoG subprocess fork)
        try:
            _cfg = yaml.safe_load(open("config.yaml")) or {}
            _miner_cfg = _cfg.get("miner", {})
        except Exception as e:
            bt.logging.debug(f"Could not read config.yaml for miner config: {e}, using defaults")
            _miner_cfg = {}

        interval_validator_update = int(_miner_cfg.get("block_interval_validator_update", 30))
        interval_specs_update = int(_miner_cfg.get("block_interval_specs_update", 150))
        interval_sync_status = int(_miner_cfg.get("block_interval_sync_status", 25))
        interval_allocation_check = int(_miner_cfg.get("block_interval_allocation_check", 15))

        block_next_updated_validator = self.current_block + interval_validator_update
        block_next_updated_specs = self.current_block + interval_specs_update
        block_next_sync_status = self.current_block + interval_sync_status

        time_next_updated_validator = None
        time_next_sync_status = None

        bt.logging.info("🚀 Starting miner loop.")
        while True:
            try:
                self.sync_local()

                if self.current_block not in self.blocks_done:
                    self.blocks_done.add(self.current_block)

                    time_next_updated_validator = self.next_info(
                        not block_next_updated_validator == 1,
                        block_next_updated_validator,
                    )
                    time_next_sync_status = self.next_info(
                        not block_next_sync_status == 1, block_next_sync_status
                    )

                if (
                    self.current_block % block_next_updated_validator == 0
                    or block_next_updated_validator < self.current_block
                ):
                    block_next_updated_validator = self.current_block + interval_validator_update
                    self.get_updated_validator()

                if (
                    self.current_block % block_next_updated_specs == 0
                    or block_next_updated_specs < self.current_block
                ):
                    block_next_updated_specs = self.current_block + interval_specs_update
                    self.wandb.update_specs()

                if (
                    self.current_block % block_next_sync_status == 0
                    or block_next_sync_status < self.current_block
                ):
                    block_next_sync_status = self.current_block + interval_allocation_check
                    self.sync_status()

                    # check allocation status
                    self.__check_alloaction_errors()

                    # Log chain data to wandb
                    chain_data = {
                        "Block": self.current_block,
                        "Stake": self._safe_get_metric(self.metagraph.S),
                        "Trust": self._safe_get_metric(self.metagraph.T),
                        "Consensus": self._safe_get_metric(self.metagraph.C),
                        "Incentive": self._safe_get_metric(self.metagraph.I),
                        "Emission": self._safe_get_metric(self.metagraph.E),
                    }
                    self.wandb.log_chain_data(chain_data)

                # Periodically clear some vars
                if len(self.blocks_done) > 1000:
                    self.blocks_done.clear()
                    self.blocks_done.add(self.current_block)

                # Sync allocation status from PoG (fast file read, no API)
                self._sync_allocation_status()

                bt.logging.info(
                    f"Block: {self.current_block} | "
                    f"Stake: {self._safe_get_metric(self.metagraph.S):.4f} | "
                    f"Trust: {self._safe_get_metric(self.metagraph.T):.4f} | "
                    f"Consensus: {self._safe_get_metric(self.metagraph.C):.6f} | "
                    f"Incentive: {self._safe_get_metric(self.metagraph.I):.6f} | "
                    f"Emission: {self._safe_get_metric(self.metagraph.E):.6f} | "
                    f"Sync_status: #{block_next_sync_status} ~ {time_next_sync_status} | "
                    f"Allocated: {'Yes' if self.allocation_status else 'No'}"
                )
                time.sleep(5)

            except (RuntimeError, Exception) as e:
                bt.logging.error(e)
                traceback.print_exc()

            # If the user interrupts the program, gracefully exit.
            except KeyboardInterrupt:
                self.stop_pog3_runner()
                self.axon.stop()
                bt.logging.success("👋 Keyboard interrupt detected. Exiting miner.")
                exit()


def main():
    """
    Main function to run the miner.

    This function initializes and runs the miner. It handles the main loop, state management, and interaction
    with the Bittensor network.
    """
    miner = Miner()
    asyncio.run(miner.start())


if __name__ == "__main__":
    main()
