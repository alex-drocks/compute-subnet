# The MIT License (MIT)
# Copyright © 2023 GitPhantomman

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
# Step 1: Import necessary libraries and modules

import bittensor as bt
import base64
import os
from io import BytesIO

from compute.utils.exceptions import make_error_response
from neurons.Miner.container import kill_container, run_container, check_container, check_allocation_key, get_docker_images_list, get_deployed_container_info
from neurons.Miner.schedule import start


# Register for given timeline and device_requirement
def register_allocation(timeline, device_requirement, public_key, docker_requirement: dict):
    # assuming allocation_status was checked before calling this
    # (it can still misfire sometimes when wandb is out of sync)
    try:
        kill_container()  # this only kills test contaienr this way, no dereg mode

        # Extract requirements from device_requirement and format them
        cpu_count = device_requirement["cpu"]["count"]  # e.g 2
        cpu_assignment = "0-" + str(cpu_count - 1)  # e.g 0-1
        if cpu_count == 1:
            cpu_assignment = "0"
        ram_capacity = device_requirement["ram"]["capacity"]  # e.g 5g
        hard_disk_capacity = device_requirement["hard_disk"]["capacity"]  # e.g 100g
        testing = device_requirement.get("testing", False)
        if not device_requirement["gpu"]:
            gpu_capacity = 0
        else:
            gpu_capacity = device_requirement["gpu"]["capacity"]  # e.g all

        cpu_usage = {"assignment": cpu_assignment}
        gpu_usage = {"capacity": gpu_capacity}
        ram_usage = {"capacity": str(int(ram_capacity / 1073741824)) + "g"}
        hard_disk_usage = {"capacity": str(int(hard_disk_capacity / 1073741824)) + "g"}

        run_status = run_container(cpu_usage, ram_usage, hard_disk_usage, gpu_usage, public_key, docker_requirement, testing)

        if run_status["status"]:
            bt.logging.info("Successfully allocated container.")

        # Kill container when it meets timeline (FIXME I don't think we actually do that)
        # start(timeline)
        return run_status

    # TODO: catch other exceptions here?
    except Exception as e:
        return make_error_response(
            f"Error allocating container {e}",
            status=False,
            exception=e,
        )

    return make_error_response(
        "This should not happen, this message probably indicates a code bug",
        status=False,
    )


# Deregister allocation
def deregister_allocation(public_key):
    try:
        file_path = 'allocation_key'
        result = kill_container(public_key=public_key)

        if result["status"]:
            # Remove the key from the file after successful deallocation
            with open(file_path, 'w') as file:
                file.truncate(0)  # Clear the file

            bt.logging.info("Successfully de-allocated container.")
            return {"status": True}
        else:
            return result
    except Exception as e:
        return make_error_response(
            f"Error de-allocating container {e}",
            status=False,
            exception=e,
        )

# Check if miner is acceptable
def check_allocation(timeline, device_requirement, checking=False):
    # If checking=True, return Docker images list and deployed container info
    if checking:
        images_result = get_docker_images_list()
        deployed_container = get_deployed_container_info()

        return {
            "status": images_result["status"],
            "images": images_result.get("images", []),
            "deployed_container": deployed_container,
            "message": images_result.get("message", "")
        }

    # Check if miner is already allocated
    if check_container() is True:
        return {"status": False}
    # Check if there is enough device
    # TODO: if we are downloading a new image we should probably start it here (but we don't pass docker reqs to this)
    return {"status": True}


def check_if_allocated(public_key):
    if not (key_check_result := check_allocation_key(public_key)).get("status"):
        return key_check_result

    try:
        # Check if the container is running
        if not check_container():
            return make_error_response(
                "Container is not running.",
                status=False,
            )

        # All checks passed, return True
        return {"status": True}
    except Exception as e:
        bt.logging.error("Container check error: {e}")
        return make_error_response(
            "Container check error: {e}",
            status=False,
            exception=e,
        )
