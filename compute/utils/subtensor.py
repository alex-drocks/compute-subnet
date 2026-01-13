# The MIT License (MIT)
# Copyright © 2023 Rapiiidooo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
import datetime
import threading
import time
from dataclasses import dataclass
from typing import Optional, Union

import bittensor as bt

from compute.utils.cache import ttl_cache

bt_blocktime = bt.BLOCKTIME


@ttl_cache(maxsize=1, ttl=bt_blocktime)
def get_current_block(subtensor: bt.subtensor) -> int:
    return subtensor.block


@dataclass
class RegistrationStatus:
    """Registration status for miners supporting off-chain mode."""
    uid: Optional[int]  # None for off-chain miners (no metagraph UID)
    is_offchain: bool
    hotkey: str
    attestation_entry: Optional[dict] = None  # Entry from attestation layer if off-chain


# Cache for off-chain registration status (avoid spamming attestation layer)
_reg_cache_lock = threading.Lock()
_reg_cache: dict = {"status": None, "ts": 0.0, "ttl": 60.0}


def _check_attestation_layer(hotkey: str, wallet) -> Optional[dict]:
    """
    Check if hotkey exists in attestation layer metagraph.
    Returns entry dict if found, None otherwise.
    """
    try:
        from neurons.Miner.pog.api_client import get_metagraph_entry
        return get_metagraph_entry(hotkey, scope="all", wallet=wallet)
    except ImportError:
        bt.logging.warning("Could not import attestation layer API client")
        return None
    except Exception as e:
        bt.logging.warning(f"Attestation layer check failed: {e}")
        return None


def is_registered(
    wallet: bt.wallet,
    metagraph: bt.metagraph,
    subtensor: bt.subtensor,
    entity: str = "validator",
    allow_offchain: bool = True,
) -> Union[int, RegistrationStatus]:
    """
    Check if wallet is registered on-chain or off-chain (attestation layer).

    Args:
        wallet: Bittensor wallet
        metagraph: Network metagraph
        subtensor: Subtensor connection
        entity: "miner" or "validator" for logging
        allow_offchain: If True, check attestation layer when not on-chain (miner only)

    Returns:
        For backward compatibility with validators (entity="validator"):
            Returns int (UID) or exits
        For miners with allow_offchain=True:
            Returns RegistrationStatus with uid (may be None) and is_offchain flag
    """
    global _reg_cache
    hotkey = wallet.hotkey.ss58_address

    # 1) Check on-chain registration first
    if hotkey in metagraph.hotkeys:
        uid = metagraph.hotkeys.index(hotkey)
        bt.logging.info(f"Running {entity} on uid: {uid}")

        # Clear off-chain cache since we're now on-chain
        with _reg_cache_lock:
            _reg_cache = {"status": None, "ts": 0.0, "ttl": 60.0}

        if entity == "miner" and allow_offchain:
            return RegistrationStatus(uid=uid, is_offchain=False, hotkey=hotkey)
        return uid

    # 2) Not on-chain - check attestation layer for miners
    if entity == "miner" and allow_offchain:
        now = time.time()

        # Thread-safe cache read
        with _reg_cache_lock:
            cached = _reg_cache.get("status")
            cache_ts = _reg_cache.get("ts", 0.0)
            cache_ttl = _reg_cache.get("ttl", 60.0)

        # Return cached status if still valid
        if cached is not None and (now - cache_ts) < cache_ttl:
            if cached.is_offchain:
                bt.logging.debug("Using cached off-chain registration status")
                return cached

        # Query attestation layer
        bt.logging.info("Hotkey not on-chain, checking attestation layer...")
        entry = _check_attestation_layer(hotkey, wallet)

        if entry is not None:
            status = RegistrationStatus(
                uid=None,  # No on-chain UID
                is_offchain=True,
                hotkey=hotkey,
                attestation_entry=entry,
            )
            # Thread-safe cache write
            with _reg_cache_lock:
                _reg_cache = {"status": status, "ts": now, "ttl": 60.0}

            bt.logging.success(
                f"Miner running in OFF-CHAIN mode (attestation layer registered). "
                f"Source: {entry.get('source', 'unknown')}, Status: {entry.get('status', 'unknown')}"
            )
            return status

        # Not found anywhere - exit
        bt.logging.error(
            f"\nYour {entity}: {wallet} is not registered on-chain or in attestation layer.\n"
            f"Run btcli register or complete attestation layer registration."
        )
        exit(1)

    # 3) Validator or off-chain disabled - use original behavior
    bt.logging.error(
        f"\nYour {entity}: {wallet} is not registered to chain connection: {subtensor}\n"
        f"Run btcli register and try again."
    )
    exit(1)


def calculate_next_block_time(block_origin, block_destiny) -> datetime.timedelta:
    return datetime.timedelta(seconds=(block_destiny - block_origin) * bt_blocktime)
