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

import bittensor as bt
import docker
from docker.types import DeviceRequest

from compute import __version_as_int__
from compute.utils.exceptions import make_error_response
import neurons.RSAEncryption as rsa

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

# Port configuration
INTERNAL_USER_PORT = 27015  # Port inside the container for user applications
# External user port is configured via --external.fixed-port flag

# XXX: global constants should be capitalized or (better) avoided
#image_name = "ssh-image"  # Docker image name
#image_name_base = "ssh-image-base"  # Docker image name
PROD_CONTAINER_NAME = "ssh-container"
TEST_CONTAINER_NAME = "ssh-test-container"
STOP_TIMEOUT = 1
WAIT_TIMEOUT = 10
container_name = "ssh-container"  # Docker container name
container_name_test = "ssh-test-container"
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

# there are exactly three places this is used:
# 1. deregister_allocation (dereg mode, has key) - normal container removal
# 2. start of register_allocation (not dereg mode, no key) - to remove test container before real allcoation
# 3. miner checking allocation status (dereg mode with empty key) - to remove any orphan containers
# maybe we need two separate ways of doing this...

# Kill the currently running container
def kill_container(public_key: str | None = None):
    if public_key is not None and (key_check_result := check_allocation_key(public_key)).get("status"):
        # "dereg mode" is the only one killing prod container
        if running_container := get_container(PROD_CONTAINER_NAME):
            if running_container.status == "running":
                running_container.stop(timeout=STOP_TIMEOUT)
                running_container.wait(timeout=WAIT_TIMEOUT)
            running_container.remove(force=True)
        bt.logging.info(f"Container '{container_name}' was killed successfully")
    elif public_key:
        return key_check_result

    # test container is always killed
    if running_container_test := get_container(TEST_CONTAINER_NAME):
        if running_container_test.status == "running":
            running_container_test.stop(timeout=STOP_TIMEOUT)
            running_container_test.wait(timeout=WAIT_TIMEOUT)
        running_container_test.remove(force=True)
        bt.logging.info(f"Container '{container_name_test}' was killed successfully")
    else:
        bt.logging.info("No running container found.")

    # Remove all dangling images
    # FIXME: probably inappropriate place for this now (we don't dangle anymore, we have a prebuilt set of images)
    # TODO: review if any regular maintenance like this should be put in some better place
    #client, _ = get_docker()
    #client.images.prune(filters={"dangling": True})
    return {"status": True}


# Run a new docker container with the given docker_name, image_name and device information
def run_container(cpu_usage, ram_usage, hard_disk_usage, gpu_usage, public_key, docker_requirement: dict, testing: bool):
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
        # TODO the value should be made mandatory and checked against a whitelist
        docker_image = docker_requirement.get("image") or "nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime"
        docker_env = docker_requirement.get("env", {})
        docker_env["NVIDIA_VISIBLE_DEVICES"] = "all"  # will need adjustment for fractional allcoations
        docker_internal_ports = docker_requirement.get("internal_ports", {"ssh": 22, "external": 27015})
        docker_external_ports = docker_requirement.get("external_ports", {"ssh": 4444, "external": 27015})
        # now let's map the two dict onto each other e.g. {22: 4444}
        ports_mapping = {
            v: docker_external_ports[k]
            for k, v in docker_internal_ports.items()
            if k in docker_external_ports
        }
        docker_ssh_key = docker_requirement.get("ssh_key")

        # Calculate 90% of free memory for shm_size
        available_memory = psutil.virtual_memory().available
        shm_size_gb = int(0.9 * available_memory / (1024**3))  # Convert to GB
        bt.logging.trace(f"Allocating {shm_size_gb}GB to /dev/shm")

        # Determine container name based on parameters (we might wanna stop doing this)
        container_to_run = TEST_CONTAINER_NAME if testing else PROD_CONTAINER_NAME

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
            restart_policy={"Name": "on-failure", "MaximumRetryCount": 3},
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
                    "fixed_external_user_port": docker_external_ports.get("external"),
                    "version": __version_as_int__
            }
            info_str = json.dumps(info)
            public_key = public_key.encode("utf-8")
            encrypted_info = rsa.encrypt_data(public_key, info_str)
            encrypted_info = base64.b64encode(encrypted_info).decode("utf-8")
            # TODO: ^^ if we stop using passwords we can get rid of this encryption stuff

            # The path to the file where you want to store the data
            file_path = 'allocation_key'
            allocation_key = base64.b64encode(public_key).decode("utf-8")

            # Open the file in write mode ('w') and write the data
            with open(file_path, 'w') as file:
                file.write(allocation_key)
            message = "Container started successfully."
            return {
                "status": True,
                "info": encrypted_info,
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


# Check if the container exists
def check_container():
    try:
        return (
            get_container(TEST_CONTAINER_NAME) is not None
            or get_container(PROD_CONTAINER_NAME) is not None
        )
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

        # Check for production container first, then test
        container = get_container(PROD_CONTAINER_NAME)
        container_name = PROD_CONTAINER_NAME

        if container is None:
            container = get_container(TEST_CONTAINER_NAME)
            container_name = TEST_CONTAINER_NAME

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
            # stop and remove the container by using the SIGTERM signal to PID 1 (init) process in the container
            if ssh_container.status == "running":
                ssh_container.stop(timeout=STOP_TIMEOUT)
                ssh_container.wait(timeout=WAIT_TIMEOUT)
            # Restart container
            ssh_container.restart()
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

    if password is not None:
        container.exec_run(cmd=f"bash -c \"echo 'root:{password}' | chpasswd\"")
    if password == '!':
        container.exec_run(cmd=f"bash -c \"echo 'root:!' | chpasswd -e\"")


# Custom templates images for pre-pull (from register-api templates)
CUSTOM_TEMPLATE_IMAGES = [
    'nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime',     # default-ubuntu-pytorch
    'nirepo/ollama-ssh:latest',                                   # ollama-ssh
    'nirepo/comfyui-ssh:latest',                                 # comfyui-ssh
    'nirepo/automatic1111-ssh:latest',                           # automatic1111-ssh
    'nirepo/scientific-ssh:latest',                              # scientific-ssh
    'nirepo/jupyter-scipy-ssh:latest',                           # jupyter-scipy-ssh
    'nirepo/jupyter-spark-ssh:latest',                           # jupyter-spark-ssh
    'nirepo/jupyter-tensorflow-ssh:latest',                      # jupyter-tensorflow-ssh
]

def pull_default_image():
    api_client = docker.APIClient()
    api_client.pull("nirepo/default-pytorch", tag="2.8.0-cuda12.8-cudnn9-runtime")

def pull_custom_template_images():
    """Pull all custom template images to avoid timeout during allocation"""
    bt.logging.info("Starting pre-pull of custom template images...")

    for image in CUSTOM_TEMPLATE_IMAGES:
        try:
            bt.logging.info(f"Pulling template image: {image}")
            result = pull_image(image)
            if result.get("status"):
                bt.logging.info(f"Successfully pulled template: {image}")
            else:
                bt.logging.warning(f"Failed to pull template {image}: {result}")
        except Exception as e:
            bt.logging.warning(f"Error pulling template {image}: {e}")

    bt.logging.info("Finished pre-pulling custom template images")


def create_check_container(name="sn27-check-container"):
    try:
        client = docker.from_env()

        # Create the container from the built image
        container = client.containers.create("nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime", name=name, command="echo compute-subnet")
        bt.logging.trace(f"Container '{container_name}' created successfully.")
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
