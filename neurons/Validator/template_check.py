#!/usr/bin/env python3
"""
Template Check Module

This module handles template availability check independently from POG and Health Check.
It runs after Health Check has finished to verify custom template images availability.
"""

import paramiko
import bittensor as bt
import time


def get_required_templates() -> list:
    """
    Get list of required custom template images.

    Note: This should be kept in sync with CUSTOM_TEMPLATE_IMAGES in miner's container.py

    Returns:
        list: List of required template image names
    """
    return [
        'nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime',     # default-ubuntu-pytorch
        'nirepo/ollama-ssh:latest',                                   # ollama-ssh
        'nirepo/comfyui-ssh:latest',                                 # comfyui-ssh
        'nirepo/automatic1111-ssh:latest',                           # automatic1111-ssh
        'nirepo/scientific-ssh:latest',                              # scientific-ssh
        'nirepo/jupyter-scipy-ssh:latest',                           # jupyter-scipy-ssh
        'nirepo/jupyter-spark-ssh:latest',                           # jupyter-spark-ssh
        'nirepo/jupyter-tensorflow-ssh:latest',                      # jupyter-tensorflow-ssh
    ]


def check_docker_images_availability(ssh_client: paramiko.SSHClient, hotkey: str = "") -> dict:
    """
    Check which custom template images are available on the miner via SSH.

    Args:
        ssh_client (paramiko.SSHClient): SSH client connected to the miner
        hotkey (str): Hotkey for logging context

    Returns:
        dict: {
            "available_templates": list,
            "missing_templates": list,
            "templates_score": float,
            "total_templates": int,
            "docker_available": bool
        }
    """
    required_templates = get_required_templates()

    try:
        # First check if docker is available
        docker_check_command = "docker --version 2>/dev/null || echo 'DOCKER_NOT_FOUND'"
        stdin, stdout, stderr = ssh_client.exec_command(docker_check_command)
        docker_output = stdout.read().decode('utf-8').strip()

        if 'DOCKER_NOT_FOUND' in docker_output:
            bt.logging.warning(f"{hotkey}: Docker not available on miner")
            return {
                "available_templates": [],
                "missing_templates": required_templates,
                "templates_score": 0.0,
                "total_templates": len(required_templates),
                "docker_available": False
            }

        # Get docker images list with repository:tag format
        images_command = "docker images --format 'table {{.Repository}}:{{.Tag}}' | grep -v 'REPOSITORY:TAG' | grep -v '^$'"
        stdin, stdout, stderr = ssh_client.exec_command(images_command)

        images_output = stdout.read().decode('utf-8').strip()
        stderr_output = stderr.read().decode('utf-8').strip()

        if stderr_output and "permission denied" in stderr_output.lower():
            bt.logging.warning(f"{hotkey}: Docker permission denied - user may not be in docker group")
            return {
                "available_templates": [],
                "missing_templates": required_templates,
                "templates_score": 0.0,
                "total_templates": len(required_templates),
                "docker_available": False
            }

        # Parse available images
        available_images = []
        if images_output:
            available_images = [img.strip() for img in images_output.split('\n') if img.strip()]

        bt.logging.trace(f"{hotkey}: Found {len(available_images)} docker images on miner")

        # Check which required templates are available
        available_templates = []
        missing_templates = []

        for template in required_templates:
            if template in available_images:
                available_templates.append(template)
                bt.logging.trace(f"{hotkey}: ✅ Template available: {template}")
            else:
                missing_templates.append(template)
                bt.logging.trace(f"{hotkey}: ❌ Template missing: {template}")

        # Calculate score
        templates_score = len(available_templates) / len(required_templates) if required_templates else 0.0

        bt.logging.info(
            f"{hotkey}: Template check - {len(available_templates)}/{len(required_templates)} "
            f"available ({templates_score:.1%})"
        )

        return {
            "available_templates": available_templates,
            "missing_templates": missing_templates,
            "templates_score": templates_score,
            "total_templates": len(required_templates),
            "docker_available": True
        }

    except Exception as e:
        bt.logging.error(f"{hotkey}: Error checking docker images: {e}")
        return {
            "available_templates": [],
            "missing_templates": required_templates,
            "templates_score": 0.0,
            "total_templates": len(required_templates),
            "docker_available": False
        }


def perform_template_check(
    axon: bt.AxonInfo,
    miner_info: dict[str, str | int],
    ssh_client: paramiko.SSHClient = None
) -> dict:
    """
    Performs template availability check on a miner.

    This function should be called after health check has passed.

    Args:
        axon: Axon information of the miner
        miner_info: Miner information (host, port, etc.) - provided by POG
        ssh_client: Existing SSH client connection from POG (optional, will create if not provided)

    Returns:
        dict: {
            "success": bool,
            "available_templates": list,
            "missing_templates": list,
            "templates_score": float,
            "total_templates": int,
            "docker_available": bool,
            "error_message": str | None
        }
    """
    hotkey = axon.hotkey
    ssh_connection_created = False

    try:
        # Use existing SSH connection from POG or create new one
        if ssh_client is None:
            host = miner_info['host']
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                bt.logging.trace(f"{hotkey}: Creating SSH connection for template check to {host}")
                ssh_client.connect(
                    host,
                    port=miner_info.get('port', 22),
                    username=miner_info['username'],
                    password=miner_info['password'],
                    timeout=10
                )
                ssh_connection_created = True
                bt.logging.trace(f"{hotkey}: SSH connection for template check successful")
            except Exception as ssh_error:
                bt.logging.error(f"{hotkey}: SSH connection for template check failed: {ssh_error}")
                return {
                    "success": False,
                    "available_templates": [],
                    "missing_templates": get_required_templates(),
                    "templates_score": 0.0,
                    "total_templates": len(get_required_templates()),
                    "docker_available": False,
                    "error_message": f"SSH connection failed: {ssh_error}"
                }
        else:
            bt.logging.trace(f"{hotkey}: Using existing SSH connection from POG for template check")

        bt.logging.debug(f"{hotkey}: Starting template availability check")

        # Perform the actual template check
        template_result = check_docker_images_availability(ssh_client, hotkey)

        # Determine overall success - requires 100% templates available
        docker_available = template_result.get("docker_available", False)
        templates_score = template_result.get("templates_score", 0.0)
        success = docker_available and templates_score >= 1.0  # Requires 100% templates

        if success:
            bt.logging.info(
                f"{hotkey}: Template check completed - "
                f"{len(template_result['available_templates'])}/{template_result['total_templates']} "
                f"templates available ({template_result['templates_score']:.1%})"
            )
        else:
            missing_templates = template_result.get("missing_templates", [])
            if missing_templates and docker_available:
                bt.logging.warning(
                    f"{hotkey}: Template check failed - Missing {len(missing_templates)} required templates:"
                )
                for i, template in enumerate(missing_templates, 1):
                    bt.logging.warning(f"{hotkey}:   {i}. {template}")
                bt.logging.info(
                    f"{hotkey}: 💡 To fix this issue, run these commands on your miner:"
                )
                for template in missing_templates:
                    bt.logging.info(f"{hotkey}:   docker pull {template}")
            else:
                bt.logging.warning(f"{hotkey}: Template check failed - Docker not available or accessible")

        return {
            "success": success,
            "available_templates": template_result["available_templates"],
            "missing_templates": template_result["missing_templates"],
            "templates_score": template_result["templates_score"],
            "total_templates": template_result["total_templates"],
            "docker_available": template_result["docker_available"],
            "error_message": None if success else (
                f"Missing {len(template_result.get('missing_templates', []))} required templates"
                if docker_available else "Docker not available or permission denied"
            )
        }

    except Exception as e:
        bt.logging.error(f"{hotkey}: Unexpected error during template check: {e}")
        return {
            "success": False,
            "available_templates": [],
            "missing_templates": get_required_templates(),
            "templates_score": 0.0,
            "total_templates": len(get_required_templates()),
            "docker_available": False,
            "error_message": f"Unexpected error: {e}"
        }

    finally:
        # Only close SSH connection if we created it
        if ssh_connection_created and ssh_client is not None:
            try:
                ssh_client.close()
                bt.logging.trace(f"{hotkey}: SSH connection for template check closed")
            except Exception as e:
                bt.logging.trace(f"{hotkey}: Error closing SSH connection for template check: {e}")
