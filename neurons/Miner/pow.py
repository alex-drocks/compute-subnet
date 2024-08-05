# The MIT License (MIT)
# Copyright © 2023 Rapiiidooo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
import shlex
import subprocess
import traceback
from typing import TypedDict, Union
import uuid

import bittensor as bt
import time

import compute

from collections import deque


queue = deque()


class PowResult(TypedDict):
    password: Union[str, None]
    local_execution_time: float
    error: Union[str, None]


def check_cuda_availability():
    import torch

    if torch.cuda.is_available():
        device_count = torch.cuda.device_count()
        bt.logging.info(f"CUDA is available with {device_count} CUDA device(s)!")
    else:
        bt.logging.warning(
            "CUDA is not available or not properly configured on this system."
        )


def hashcat_verify(_hash, output) -> Union[str, None]:
    for item in output.split("\n"):
        if _hash in item:
            return item.strip().split(":")[-1]
    return None


def run_hashcat(
    run_id: str,
    _hash: str,
    salt: str,
    mode: str,
    chars: str,
    mask: str,
    timeout: int = compute.pow_timeout,
    hashcat_path: str = compute.miner_hashcat_location,
    hashcat_workload_profile: str = compute.miner_hashcat_workload_profile,
    session: str = None,
):
    start_time = time.time()

    bt.logging.info(f"{run_id}: ♻️  Challenge processing")

    try:
        command = [
            hashcat_path,
            f"{_hash}:{salt}",
            "-a",
            "3",
            "-D",
            "2",
            "-m",
            mode,
            "-1",
            str(chars),
            mask,
            "-w",
            hashcat_workload_profile,
            "--session",
            session,
            "--optimized-kernel-enable",
        ]
        command_str = " ".join(shlex.quote(arg) for arg in command)
        bt.logging.trace(command_str)

        process = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )

        execution_time = time.time() - start_time

        if process.returncode == 0 and process.stdout:
            result = hashcat_verify(_hash, process.stdout)
            if result:
                bt.logging.success(
                    f"{run_id}: ✅ Challenge {result} found in {execution_time:0.2f} seconds !"
                )
                return {
                    "password": result,
                    "local_execution_time": execution_time,
                    "error": None,
                }
        error_message = f"{run_id}: ❌ Hashcat execution failed with code {process.returncode}: {process.stderr}"
        bt.logging.warning(error_message)
        return {
            "password": None,
            "local_execution_time": execution_time,
            "error": error_message,
        }

    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        error_message = (
            f"{run_id}: ❌ Hashcat execution timed out ({execution_time:0.2f})"
        )
        bt.logging.warning(error_message)
        return {
            "password": None,
            "local_execution_time": execution_time,
            "error": error_message,
        }
    except Exception as e:
        execution_time = time.time() - start_time
        traceback.print_exc()
        unknown_error_message = f"{run_id}: ❌ run_hashcat execution failed"
        bt.logging.warning(f"{unknown_error_message}: {e}")
        return {
            "password": None,
            "local_execution_time": execution_time,
            "error": f"{unknown_error_message}: {e}",
        }


def run_miner_pow(
    run_id: str,
    _hash: str,
    salt: str,
    mode: str,
    chars: str,
    mask: str,
    hashcat_path: str = compute.miner_hashcat_location,
    hashcat_workload_profile: str = compute.miner_hashcat_workload_profile,
    hashcat_extended_options: str = compute.miner_hashcat_extended_options,
) -> PowResult:
    try:
        queue.append(run_id)
        result: PowResult = run_hashcat(
            run_id=run_id,
            _hash=_hash,
            salt=salt,
            mode=mode,
            chars=chars,
            mask=mask,
            hashcat_path=hashcat_path,
            hashcat_workload_profile=hashcat_workload_profile,
            session=str(uuid.uuid4()).replace("-", ""),
            timeout=compute.pow_timeout,
        )
    finally:
        queue.remove(run_id)

    return result
