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

import base64
import json
import os
import psutil
import secrets
import string
import subprocess
import sys
from io import BytesIO
from typing import List, Optional, Tuple

import bittensor as bt
import docker
import yaml
from docker.types import DeviceRequest

from compute import __version_as_int__
from compute.utils.exceptions import make_error_response
import neurons.RSAEncryption as rsa

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# Port configuration
INTERNAL_USER_PORTS = [27015, 27016, 27017, 27018]  # Ports inside the container for user applications
# External user ports are configured via --external.ports flag

# XXX: global constants should be capitalized or (better) avoided
#image_name = "ssh-image"  # Docker image name
#image_name_base = "ssh-image-base"  # Docker image name
PROD_CONTAINER_NAME = "ssh-container"
TEST_CONTAINER_PREFIX = "ssh-test-"  # Per-validator test containers: ssh-test-{hotkey[:12]}
STOP_TIMEOUT = 1
WAIT_TIMEOUT = 10
DEFAULT_TEST_CONTAINER_TTL_SEC = 10  # Default TTL for test containers
DEFAULT_TEST_SSH_PORT = 4445  # Default SSH port for test containers (different from prod)
container_name = "ssh-container"  # Docker container name (legacy, use PROD_CONTAINER_NAME)
container_name_test = "ssh-test-container"  # Legacy, now using per-validator naming


def get_test_container_name(validator_hotkey: str) -> str:
    """Generate per-validator test container name using first 12 chars of hotkey."""
    return f"{TEST_CONTAINER_PREFIX}{validator_hotkey[:12]}"


def _load_docker_image_whitelist() -> List[str]:
    """Load Docker image whitelist from config.yaml.

    Returns:
        List of allowed image patterns. Empty list means no whitelist (allow all - DANGEROUS).
    """
    try:
        with open("config.yaml", "r") as f:
            cfg = yaml.safe_load(f) or {}
        whitelist = cfg.get("miner", {}).get("docker_image_whitelist", [])
        if isinstance(whitelist, list):
            return [str(img) for img in whitelist if img]
        return []
    except Exception as e:
        bt.logging.debug(f"Could not load docker image whitelist: {e}")
        # Return default whitelist if config can't be read
        return [
            "nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime",
            "nirepo/",
        ]


def validate_docker_image(image: str) -> Tuple[bool, str]:
    """Validate that a Docker image is in the whitelist.

    Args:
        image: The Docker image name to validate.

    Returns:
        Tuple of (is_valid, message). is_valid is True if image is allowed.
    """
    if not image:
        return False, "No image specified"

    whitelist = _load_docker_image_whitelist()

    # Empty whitelist = no restriction (dangerous but configurable)
    if not whitelist:
        bt.logging.warning("Docker image whitelist is empty - allowing any image (DANGEROUS)")
        return True, "No whitelist configured"

    # Check against whitelist (exact match or prefix match)
    for pattern in whitelist:
        if not pattern:
            continue
        # Exact match
        if image == pattern:
            return True, f"Image matches whitelist entry: {pattern}"
        # Prefix match (for registry/namespace patterns like "nirepo/")
        if pattern.endswith("/") or pattern.endswith(":"):
            if image.startswith(pattern):
                return True, f"Image matches whitelist prefix: {pattern}"

    # Not in whitelist
    return False, f"Image '{image}' is not in the allowed whitelist. Allowed: {whitelist}"


def is_allocation_owner(public_key: str) -> bool:
    """Check if the given public_key matches the current allocation owner.

    Args:
        public_key: The public key to check against the stored allocation key.

    Returns:
        True if the public_key matches the allocation owner, False otherwise.
    """
    try:
        file_path = 'allocation_key'
        if not os.path.exists(file_path):
            return False

        with open(file_path, 'r') as file:
            allocation_key_encoded = file.read().strip()

        if not allocation_key_encoded:
            return False

        allocation_key = base64.b64decode(allocation_key_encoded).decode('utf-8')
        return allocation_key.strip() == public_key.strip()
    except Exception as e:
        bt.logging.debug(f"Error checking allocation ownership: {e}")
        return False


def has_active_production_allocation() -> bool:
    """Check if there's an active production allocation (prod container + valid allocation key).

    Returns:
        True if there's an active production allocation, False otherwise.
    """
    prod_container = get_container(PROD_CONTAINER_NAME)
    if prod_container is None or prod_container.status != "running":
        return False

    # Also check that allocation_key file exists and has content
    try:
        file_path = 'allocation_key'
        if not os.path.exists(file_path):
            return False
        with open(file_path, 'r') as file:
            return bool(file.read().strip())
    except Exception:
        return False


volume_name = "ssh-volume"  # Docker volumne name
volume_path = "/tmp"  # Path inside the container where the volume will be mounted
ssh_port = 4444  # Port to map SSH service on the host

# Initialize Docker client
def get_docker():
    client = docker.from_env()
    containers = client.containers.list(all=True)
    return client, containers


def get_container(name: str):
    client, containers = get_docker()
    for container in containers:
        if container.name == name:
            return container
    return None


def get_all_test_containers():
    """Get all test containers (those starting with TEST_CONTAINER_PREFIX)."""
    client, containers = get_docker()
    return [c for c in containers if c.name.startswith(TEST_CONTAINER_PREFIX)]


def get_test_container_for_validator(validator_hotkey: str):
    """Get the test container for a specific validator."""
    container_name = get_test_container_name(validator_hotkey)
    return get_container(container_name)

# there are exactly three places this is used:
# 1. deregister_allocation (dereg mode, has key) - normal container removal
# 2. start of register_allocation (not dereg mode, no key) - to remove test container before real allcoation
# 3. miner checking allocation status (dereg mode with empty key) - to remove any orphan containers
# maybe we need two separate ways of doing this...


def kill_test_container_for_validator(validator_hotkey: str):
    """Kill the test container for a specific validator.

    Args:
        validator_hotkey: The validator's hotkey to identify their test container.

    Returns:
        dict with status and message.
    """
    container_name = get_test_container_name(validator_hotkey)
    container = get_container(container_name)

    if container is None:
        bt.logging.debug(f"No test container found for validator {validator_hotkey[:8]}")
        return {"status": True, "message": "No test container to kill"}

    try:
        if container.status == "running":
            container.stop(timeout=STOP_TIMEOUT)
            container.wait(timeout=WAIT_TIMEOUT)
        container.remove(force=True)
        bt.logging.info(f"Test container '{container_name}' killed successfully")
        return {"status": True, "message": f"Test container {container_name} killed"}
    except Exception as e:
        bt.logging.error(f"Error killing test container {container_name}: {e}")
        return {"status": False, "message": str(e)}


def cleanup_stale_test_containers(max_age_seconds: int = DEFAULT_TEST_CONTAINER_TTL_SEC):
    """Clean up test containers older than max_age_seconds.

    Args:
        max_age_seconds: Maximum age in seconds before a test container is considered stale.
                        Default is 10 seconds.

    Returns:
        Number of containers cleaned up.
    """
    import time
    from datetime import datetime

    cleaned = 0
    test_containers = get_all_test_containers()

    for container in test_containers:
        try:
            # Get container creation time
            container.reload()
            created_str = container.attrs.get('Created', '')
            if not created_str:
                continue

            # Parse ISO format timestamp (Docker uses ISO 8601)
            # Format: "2024-01-15T10:30:00.123456789Z"
            created_str = created_str.split('.')[0]  # Remove nanoseconds
            created_time = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            age_seconds = (datetime.now(created_time.tzinfo) - created_time).total_seconds()

            if age_seconds > max_age_seconds:
                bt.logging.info(f"Cleaning up stale test container '{container.name}' (age: {age_seconds:.1f}s, status: {container.status})")
                try:
                    if container.status == "running":
                        container.stop(timeout=STOP_TIMEOUT)
                        container.wait(timeout=WAIT_TIMEOUT)
                except Exception:
                    pass  # Container may already be stopped or in transitional state
                container.remove(force=True)
                cleaned += 1
        except Exception as e:
            bt.logging.warning(f"Error cleaning up test container {container.name}: {e}")

    if cleaned > 0:
        bt.logging.info(f"Cleaned up {cleaned} stale test container(s)")
    return cleaned


def wait_for_test_port(port: int, timeout: float = 15.0) -> bool:
    """Wait for test port to become available.

    Args:
        port: The port to wait for.
        timeout: Maximum time to wait in seconds.

    Returns:
        True if port is available, False if timeout.
    """
    import time
    start = time.time()
    while time.time() - start < timeout:
        # Check if any test container is using the port
        test_containers = get_all_test_containers()
        port_in_use = False
        for container in test_containers:
            try:
                container.reload()
                ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
                for port_binding in ports.values():
                    if port_binding and any(p.get('HostPort') == str(port) for p in port_binding):
                        port_in_use = True
                        break
            except Exception:
                continue
            if port_in_use:
                break

        if not port_in_use:
            return True

        bt.logging.debug(f"Test port {port} busy, waiting...")
        time.sleep(1.0)

    return False


def cleanup_containers_on_port(port: int):
    """Force cleanup any test containers bound to the given port.

    Args:
        port: The port to cleanup.

    Returns:
        Number of containers cleaned up.
    """
    cleaned = 0
    test_containers = get_all_test_containers()
    for container in test_containers:
        try:
            container.reload()
            ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
            for port_binding in ports.values():
                if port_binding and any(p.get('HostPort') == str(port) for p in port_binding):
                    bt.logging.info(f"Force removing container {container.name} holding port {port}")
                    try:
                        container.stop(timeout=2)
                    except Exception:
                        pass
                    container.remove(force=True)
                    cleaned += 1
                    break
        except Exception as e:
            bt.logging.debug(f"Error checking container {container.name}: {e}")
    return cleaned


# Kill the currently running container
def kill_container(public_key: str | None = None, kill_test: bool = True, force_kill_prod: bool = False, validator_hotkey: str | None = None):
    """Kill running containers.

    Args:
        public_key: Allocation key for authorization. None or empty string for orphan cleanup.
        kill_test: Whether to kill test containers. If validator_hotkey is provided, only kills
                   that validator's test container. Otherwise kills all test containers (legacy behavior).
        force_kill_prod: If True, kill prod container without key verification.
                         Used for orphan cleanup when no allocation key file exists.
        validator_hotkey: If provided with kill_test=True, only kills this validator's test container.
    """
    prod_killed = False

    # Force kill prod container (for orphan cleanup - no key file exists)
    if force_kill_prod:
        if running_container := get_container(PROD_CONTAINER_NAME):
            if running_container.status == "running":
                running_container.stop(timeout=STOP_TIMEOUT)
                running_container.wait(timeout=WAIT_TIMEOUT)
            running_container.remove(force=True)
            bt.logging.info(f"Container '{PROD_CONTAINER_NAME}' was force-killed (orphan cleanup)")
            prod_killed = True
    elif public_key is not None and (key_check_result := check_allocation_key(public_key)).get("status"):
        # "dereg mode" - kill prod container with valid key
        if running_container := get_container(PROD_CONTAINER_NAME):
            if running_container.status == "running":
                running_container.stop(timeout=STOP_TIMEOUT)
                running_container.wait(timeout=WAIT_TIMEOUT)
            running_container.remove(force=True)
            prod_killed = True
            bt.logging.info(f"Container '{PROD_CONTAINER_NAME}' was killed successfully")
    elif public_key:
        return key_check_result

    # Kill test container(s) if requested
    if kill_test:
        if validator_hotkey:
            # Kill only this validator's test container
            kill_test_container_for_validator(validator_hotkey)
        else:
            # Legacy behavior: kill all test containers
            test_containers = get_all_test_containers()
            if test_containers:
                for test_container in test_containers:
                    try:
                        if test_container.status == "running":
                            test_container.stop(timeout=STOP_TIMEOUT)
                            test_container.wait(timeout=WAIT_TIMEOUT)
                        test_container.remove(force=True)
                        bt.logging.info(f"Test container '{test_container.name}' was killed successfully")
                    except Exception as e:
                        bt.logging.warning(f"Error killing test container {test_container.name}: {e}")
            elif not prod_killed:
                bt.logging.info("No running container found.")

    return {"status": True}


# Run a new docker container with the given docker_name, image_name and device information
def run_container(cpu_usage, ram_usage, hard_disk_usage, gpu_usage, public_key, docker_requirement: dict, testing: bool, validator_hotkey: str | None = None, test_ssh_port: int = DEFAULT_TEST_SSH_PORT):
    try:
        client, containers = get_docker()
        # Configuration
        password = password_generator(10)  # let's deprecate password, it creates all kind of issues
        cpu_assignment = cpu_usage["assignment"]  # e.g : 0-1
        ram_limit = ram_usage["capacity"]  # e.g : 5g
        hard_disk_capacity = hard_disk_usage["capacity"]  # e.g : 100g
        gpu_capacity = gpu_usage["capacity"]  # e.g : all
        # XXX ^^ here we take all the device requirements are ignore them completely

        # new template settings
        docker_image = docker_requirement.get("image") or "nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime"

        # Validate image against whitelist (security check)
        is_valid, validation_msg = validate_docker_image(docker_image)
        if not is_valid:
            bt.logging.warning(f"Docker image rejected: {validation_msg}")
            return make_error_response(
                f"Docker image not allowed: {docker_image}. Only whitelisted images are permitted.",
                status=False,
                exception=None,
            )
        bt.logging.debug(f"Docker image validated: {validation_msg}")

        docker_env = docker_requirement.get("env", {})
        docker_env["NVIDIA_VISIBLE_DEVICES"] = "all"  # will need adjustment for fractional allcoations
        docker_internal_ports = docker_requirement.get("internal_ports", {"ssh": 22})
        docker_external_ports = docker_requirement.get("external_ports", {"ssh": 4444})

        # For test containers, use different SSH port to avoid conflicts with production
        if testing:
            docker_external_ports = {"ssh": test_ssh_port}
            # Test containers don't use external_user_ports to avoid port conflicts
            external_user_ports = {}
            bt.logging.debug(f"Test container using SSH port {test_ssh_port}")
        else:
            # Get external_user_ports for multiple port support (production only)
            external_user_ports = docker_requirement.get("external_user_ports", {})

        # now let's map the two dict onto each other e.g. {22: 4444}
        ports_mapping = {
            v: docker_external_ports[k]
            for k, v in docker_internal_ports.items()
            if k in docker_external_ports
        }
        docker_ssh_key = docker_requirement.get("ssh_key")

        # Merge external_user_ports into ports_mapping (production only)
        for internal_port, external_port in external_user_ports.items():
            ports_mapping[int(internal_port)] = external_port

        # Calculate 90% of free memory for shm_size
        available_memory = psutil.virtual_memory().available
        shm_size_gb = int(0.9 * available_memory / (1024**3))  # Convert to GB
        bt.logging.trace(f"Allocating {shm_size_gb}GB to /dev/shm")

        # Determine container name based on parameters
        if testing:
            if validator_hotkey:
                container_to_run = get_test_container_name(validator_hotkey)
            else:
                # Fallback for legacy calls without hotkey (shouldn't happen in normal flow)
                bt.logging.warning("Test container requested without validator_hotkey, using legacy name")
                container_to_run = f"{TEST_CONTAINER_PREFIX}legacy"
        else:
            container_to_run = PROD_CONTAINER_NAME

        # Step 2: Run the Docker container

        # Create the Docker volume with the specified size
        # client.volumes.create(volume_name, driver = 'local', driver_opts={'size': hard_disk_capacity})

        device_requests = [DeviceRequest(count=-1, capabilities=[["gpu"]])]
        # if gpu_usage["capacity"] == 0:
        #    device_requests = []
        container = client.containers.run(
            image=docker_image,
            name=container_to_run,
            detach=True,
            device_requests=device_requests,
            environment=[f"{k}={v}" for k, v in docker_env.items()],
            ports=ports_mapping,
            init=False,
            shm_size=f"{shm_size_gb}g",  # Set the shared memory size to 2GB
            restart_policy={"Name": "unless-stopped"},
            # volumes={ docker_volume: {'bind': '/root/workspace/', 'mode': 'rw'}},
        )

        # Get deployed image digest for validation
        deployed_image_info = None
        try:
            deployed_image = client.images.get(docker_image)
            repo_digests = deployed_image.attrs.get('RepoDigests', [])
            digest = None
            if repo_digests:
                # Extract digest from format "repository@sha256:..."
                for repo_digest in repo_digests:
                    if '@' in repo_digest:
                        digest = repo_digest.split('@')[1]
                        break

            deployed_image_info = {
                "image": docker_image,
                "digest": digest
            }
            bt.logging.trace(f"Deployed image: {docker_image}, digest: {digest}")
        except Exception as e:
            bt.logging.warning(f"Failed to get deployed image digest: {e}")
            deployed_image_info = {
                "image": docker_image,
                "digest": None
            }

        # Check the status to determine if the container ran successfully
        if container.status == "created":
            bt.logging.info("Container was created successfully.")

            exec_update_container_key(container, new_ssh_key=docker_ssh_key, key_type="user", password=password)
            bt.logging.info("Container ssh key set.")

            info = {
                    "username": "root",
                    "password": password,
                    "port": docker_external_ports["ssh"],
                    "external_user_ports": external_user_ports,
                    "version": __version_as_int__
            }
            info_str = json.dumps(info)

            # Support optional RSA encryption for backwards compatibility
            if public_key:
                # Old path: encrypt for validators that send a public key
                public_key_bytes = public_key.encode("utf-8")
                encrypted_info = rsa.encrypt_data(public_key_bytes, info_str)
                encoded_info = base64.b64encode(encrypted_info).decode("utf-8")
            else:
                # New path: plain JSON (base64 encoded) for validators that skip RSA
                encoded_info = base64.b64encode(info_str.encode("utf-8")).decode("utf-8")

            # Store allocation key for production containers only
            # Test containers should NOT overwrite the allocation_key (it belongs to prod allocation)
            if not testing and public_key:
                file_path = 'allocation_key'
                allocation_key = base64.b64encode(public_key.encode("utf-8")).decode("utf-8")

                # Write with restrictive permissions (owner read/write only)
                fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.write(fd, allocation_key.encode("utf-8"))
                finally:
                    os.close(fd)

            message = "Container started successfully."
            return {
                "status": True,
                "info": encoded_info,
                "message": message,
                "deployed_image": deployed_image_info
            }
        else:
            return make_error_response(
                f"Container failed with status: {container.status}",
                status=False,
                exception=None,
            )

    except docker.errors.ContainerError as e:
        return make_error_response(
            f"Container failed to run {e}",
            status=False,
            exception=e,
        )
    except docker.errors.APIError as e:
        return make_error_response(
            f"Docker error while starting container {e}",
            status=False,
            exception=e,
        )
    except docker.errors.ImageNotFound as e:
        return make_error_response(
            f"Image not found for starting container {e}",
            status=False,
            exception=e,
        )
    except Exception as e:
        return make_error_response(
            f"Error running container {e}",
            status=False,
            exception=e,
        )


# Check if the container exists and is running
def check_container():
    """Check if a production container is running.

    Note: Test containers do NOT block availability. Each validator can have their own
    test container running concurrently. Only production containers indicate the miner
    is busy with a real allocation.

    Returns:
        True if production container is running (miner is busy), False otherwise (available).
    """
    try:
        # Only check production container - test containers don't block availability
        prod_container = get_container(PROD_CONTAINER_NAME)
        if prod_container is not None and prod_container.status == "running":
            return True

        return False
    except Exception as e:
        bt.logging.info(f"Error checking container {e}")
        return False


def get_deployed_container_info():
    """
    Get info about currently deployed container and its image.

    Returns:
        dict: {
            "has_container": bool,
            "container_name": str | None,
            "deployed_image": {
                "image": str,
                "digest": str | None
            } | None
        }
    """
    try:
        client = docker.from_env()

        # Check for production container first
        container = get_container(PROD_CONTAINER_NAME)
        container_name = PROD_CONTAINER_NAME

        # If no prod container, check for any test containers
        if container is None:
            test_containers = get_all_test_containers()
            if test_containers:
                # Return info about the first test container found
                container = test_containers[0]
                container_name = container.name

        if container is None:
            return {
                "has_container": False,
                "container_name": None,
                "deployed_image": None
            }

        # Get image info from running container
        image_name = container.image.tags[0] if container.image.tags else None

        if image_name:
            try:
                image = client.images.get(image_name)
                repo_digests = image.attrs.get('RepoDigests', [])
                digest = None

                if repo_digests:
                    for repo_digest in repo_digests:
                        if '@' in repo_digest:
                            digest = repo_digest.split('@')[1]
                            break

                return {
                    "has_container": True,
                    "container_name": container_name,
                    "deployed_image": {
                        "image": image_name,
                        "digest": digest
                    }
                }
            except Exception as e:
                bt.logging.warning(f"Error getting deployed image info: {e}")
                return {
                    "has_container": True,
                    "container_name": container_name,
                    "deployed_image": {
                        "image": image_name,
                        "digest": None
                    }
                }

        return {
            "has_container": True,
            "container_name": container_name,
            "deployed_image": None
        }

    except Exception as e:
        bt.logging.error(f"Error in get_deployed_container_info: {e}")
        return {
            "has_container": False,
            "container_name": None,
            "deployed_image": None
        }


# Randomly generate password for given length
def password_generator(length):
    alphabet = string.ascii_letters + string.digits  # You can customize this as needed
    random_str = "".join(secrets.choice(alphabet) for _ in range(length))
    return random_str


def retrieve_allocation_key():
    try:
        file_path = 'allocation_key'
         # Open the file in read mode ('r') and read the data
        with open(file_path, 'r') as file:
            allocation_key_encoded = file.read()

        # Decode the base64-encoded public key from the file
        allocation_key = base64.b64decode(allocation_key_encoded).decode('utf-8')
        return allocation_key
    except Exception as e:
        bt.logging.info(f"Error retrieving allocation key.", exc_info=True)
        return None


def check_allocation_key(public_key: str):
    try:
        file_path = 'allocation_key'
         # Open the file in read mode ('r') and read the data
        with open(file_path, 'r') as file:
            allocation_key_encoded = file.read()

        # Decode the base64-encoded public key from the file
        allocation_key = base64.b64decode(allocation_key_encoded).decode('utf-8')
    except FileNotFoundError:
        # Expected when no production allocation exists - no logging needed
        return make_error_response("No active allocation.", status=False)
    except Exception as e:
        bt.logging.info("Error retrieving allocation key.", exc_info=True)
        return make_error_response(
            "Failed to retrieve allocation key.",
            status=False,
            exception=e,
        )
    # compare public_key to the local saved allocation key for security
    if allocation_key.strip() == public_key.strip():
        return {"status": True}
    else:
        return make_error_response(
            "Permission denied (allocation key mismatch).",
            status=False,
        )


def restart_container(public_key: str):
    if not (key_check_result := check_allocation_key(public_key)).get("status"):
        return key_check_result

    try:
        if ssh_container := get_container(PROD_CONTAINER_NAME):
            # restart and reload the container
            # Restart container
            ssh_container.restart(timeout=STOP_TIMEOUT)  # this includes stop with kill fallback
            # Reload the container to get updated information
            ssh_container.reload()
            if ssh_container.status == "running":
                return {
                    "status": True,
                    "message": "Container restarted successfully."
                }
            else:
                return make_error_response(
                    f"Failed to restart container. Status {ssh_container.status}",
                    status=False,
                )

        else:
            return make_error_response(
                f"No running container.",
                status=False,
            )
    except Exception as e:
        return make_error_response(
            f"Error restart container: {e}",
            status=False,
            exception=e,
        )

def pause_container(public_key: str):
    if not (key_check_result := check_allocation_key(public_key)).get("status"):
        return key_check_result
    try:
        if running_container := get_container(PROD_CONTAINER_NAME):
            running_container.pause()
            return {
                "status": True,
                "message": "Container paused successfully."
            }
        else:
            return make_error_response(
                "Unable to find container",
                status=False,
            )
    except Exception as e:
        return make_error_response(
            f"Error pausing container {e}",
            status=False,
            exception=e,
        )

def unpause_container(public_key: str):
    if not (key_check_result := check_allocation_key(public_key)).get("status"):
        return key_check_result
    try:
        if running_container := get_container(PROD_CONTAINER_NAME):
            running_container.unpause()
            return {
                "status": True,
                "message": "Container un-paused successfully."
            }
        else:
            return make_error_response(
                "Unable to find container",
                status=False,
            )
    except Exception as e:
        return make_error_response(
            f"Error unpausing container {e}",
            status=False,
            exception=e,
        )


def exchange_key_container(new_ssh_key: str, public_key: str, key_type: str = "user"):
    if not (key_check_result := check_allocation_key(public_key)).get("status"):
        return key_check_result
    try:
        if running_container := get_container(PROD_CONTAINER_NAME):
            if running_container.status == "running":
                exec_update_container_key(running_container, new_ssh_key=new_ssh_key, key_type=key_type)
            return {
                "status": True,
                "message": "Container key exchanged successfully."
            }
        else:
            return make_error_response(
                "Unable to find container",
                status=False,
            )
    except Exception as e:
        return make_error_response(
            f"Error changing SSH key on container {e}",
            status=False,
            exception=e,
        )


def exec_update_container_key(container, new_ssh_key: str, key_type: str = "user", password: str | None = None):
    if key_type not in ["user", "terminal"]:
        raise ValueError("Unknown key_type, this is likely a code bug.")

    exit_code, exist_key = container.exec_run(cmd="bash -c \"[ -f /root/.ssh/authorized_keys ] && cat /root/.ssh/authorized_keys || ( mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys )\"")
    if exit_code != 0:
        raise RuntimeError(f"Failed to read existing ssh key: {exist_key}")

    exist_key = exist_key.decode("utf-8").split("\n")
    user_key = exist_key[0] or ""
    terminal_key = ""
    if len(exist_key) > 1:
        terminal_key = exist_key[1]
    if key_type == "terminal":
        terminal_key = new_ssh_key
    elif key_type == "user":
        user_key = new_ssh_key
    else:
        assert False, "Unknown key type"
    key_list = '\n'.join([user_key or "", terminal_key or ""])
    # bt.logging.debug(f"New SSH key: {key_list}")
    container.exec_run(cmd=f"bash -c \"echo '{key_list}' > /root/.ssh/authorized_keys && sync\"")

    # Ensure SSH service is running after key update (required for custom templates)
    exit_code, output = container.exec_run(cmd="bash -c \"service ssh start 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true\"")
    if exit_code == 0:
        bt.logging.info("SSH service started/restarted after key update")
    else:
        bt.logging.warning(f"Could not start SSH service: {output.decode('utf-8') if output else 'unknown error'}")

    if password is not None:
        container.exec_run(cmd=f"bash -c \"echo 'root:{password}' | chpasswd\"")
    if password == '!':
        container.exec_run(cmd=f"bash -c \"echo 'root:!' | chpasswd -e\"")


# Custom templates images for pre-pull (from register-api templates)
CUSTOM_TEMPLATE_IMAGES = [
    'nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime',     # default-ubuntu-pytorch
    'nirepo/scientific-ssh:latest',                              # scientific-ssh
    'nirepo/jupyter-scipy-ssh:latest',                           # jupyter-scipy-ssh
    'nirepo/jupyter-spark-ssh:latest',                           # jupyter-spark-ssh
    'nirepo/jupyter-pytorch-ssh:latest',                         # jupyter-pytorch-ssh
    'nirepo/jupyter-tensorflow-ssh:latest',                      # jupyter-tensorflow-ssh
    'nirepo/datascience-ssh:latest',                             # datascience-ssh
]

def pull_default_image():
    api_client = docker.APIClient()
    api_client.pull("nirepo/default-pytorch", tag="2.8.0-cuda12.8-cudnn9-runtime")


def _image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    try:
        client = docker.from_env()
        client.images.get(image)
        return True
    except docker.errors.ImageNotFound:
        return False
    except Exception:
        return False


def pull_custom_template_images():
    """Pull all custom template images to avoid timeout during allocation"""

    # Check which images need to be pulled
    images_to_pull = []
    for image in CUSTOM_TEMPLATE_IMAGES:
        if not _image_exists(image):
            images_to_pull.append(image)

    if not images_to_pull:
        bt.logging.info(f"All {len(CUSTOM_TEMPLATE_IMAGES)} template images already present, skipping pull")
        return

    bt.logging.info(
        f"Downloading {len(images_to_pull)} template images "
        f"({len(CUSTOM_TEMPLATE_IMAGES) - len(images_to_pull)} already present). "
        f"This may take a few minutes on first run..."
    )

    for image in images_to_pull:
        try:
            bt.logging.info(f"Pulling template image: {image}")
            result = pull_image(image)
            if result.get("status"):
                bt.logging.debug(f"Successfully pulled: {image}")
            else:
                bt.logging.warning(f"Failed to pull template {image}: {result}")
        except Exception as e:
            bt.logging.warning(f"Error pulling template {image}: {e}")

    bt.logging.info(f"Finished pulling {len(images_to_pull)} template images")


def create_check_container(name="sn27-check-container"):
    try:
        client = docker.from_env()

        # Create the container from the built image
        container = client.containers.create("nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime", name=name, command="echo compute-subnet")
        bt.logging.trace(f"Container '{name}' created successfully.")
        return container

    except docker.errors.APIError as e:
        pass
    except Exception as e:
        bt.logging.error(
            "Insufficient permissions to execute Docker commands. Please ensure the current user is added to the 'docker' group "
            "and has the necessary privileges. Run 'sudo usermod -aG docker $USER' and restart your session."
        )
    finally:
        try:
            client.close()
        except Exception as close_error:
            bt.logging.warning(f"Error closing the Docker client: {close_error}")


def pull_image(image: str = ''):
    if not image:
        image = "nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime"
    name, tag = image.split(':', 1)
    api_client = docker.APIClient()
    try:
        # Pull the image and consume the stream to actually download it
        for line in api_client.pull(name, tag=tag, stream=True, decode=True):
            if 'status' in line:
                bt.logging.trace(f"Pull {image}: {line['status']}")

        message = f"Container image {image} pulled successfully"
        bt.logging.info(message)
        return {"status": True, "message": message}
    except docker.errors.APIError as e:
        return make_error_response(
            "Pull image failed with exception",
            status=False,
            exception=e,
        )
    except Exception as e:
        return make_error_response(
            "Pull image failed with unknown exception",
            status=False,
            exception=e,
        )


def get_docker_images_list() -> dict:
    """
    Get list of all Docker images with their RepoDigests using Docker API.

    Returns:
        dict: {
            "status": bool,
            "images": list[dict] with {repository, tag, digest},
            "message": str
        }
    """
    try:
        client = docker.from_env()
        images = client.images.list(all=True)

        images_list = []
        for image in images:
            # Get RepoDigests (manifest digests from registry)
            repo_digests = image.attrs.get('RepoDigests', [])

            # Get image tags
            tags = image.tags if image.tags else []

            if tags:
                for tag in tags:
                    # Parse repository:tag format
                    if ':' in tag:
                        repository, image_tag = tag.rsplit(':', 1)
                    else:
                        repository = tag
                        image_tag = 'latest'

                    # Find matching digest for this repo
                    matching_digest = None
                    for digest in repo_digests:
                        if digest.startswith(f"{repository}@"):
                            matching_digest = digest.split('@')[1]
                            break

                    images_list.append({
                        "repository": repository,
                        "tag": image_tag,
                        "digest": matching_digest,
                        "full_name": f"{repository}:{image_tag}"
                    })

        bt.logging.trace(f"Retrieved {len(images_list)} Docker images with digests")
        return {
            "status": True,
            "images": images_list,
            "message": f"Successfully retrieved {len(images_list)} images"
        }

    except docker.errors.DockerException as e:
        bt.logging.error(f"Docker error while listing images: {e}")
        return {
            "status": False,
            "images": [],
            "message": f"Docker error: {str(e)}"
        }
    except Exception as e:
        bt.logging.error(f"Error listing Docker images: {e}")
        return {
            "status": False,
            "images": [],
            "message": f"Error: {str(e)}"
        }
