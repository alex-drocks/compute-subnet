#!/usr/bin/env python3
"""
Template Check Module

This module handles template availability check using Allocate request with checking=True.
It verifies custom template images availability and validates their digests.
"""

import bittensor as bt
from compute.protocol import Allocate


# Expected digests for template images verification (SHA256 manifest digests from Docker Hub)
TEMPLATE_EXPECTED_DIGESTS = {
    'nirepo/default-pytorch:2.8.0-cuda12.8-cudnn9-runtime': 'sha256:75c5f262ff46a0b4eb84d914c9f0740d5fc79478a366085fbfd6bce51f48cfe9',
    'nirepo/ollama-ssh:latest': 'sha256:b689dee49d9b03753d6f76e5ab2f4d6b655d1080234bcc070b1f54e937f233c5',
    'nirepo/comfyui-ssh:latest': 'sha256:312411098589ca6e8b557589f4dcf5be2a2367045f724ffe807befc4bedc14f1',
    'nirepo/automatic1111-ssh:latest': 'sha256:5a6da72aabccd04a897706052191db61876dfdc5461b51feebfb1b61912b5e6a',
    'nirepo/scientific-ssh:latest': 'sha256:40c93cdcba24212a71f9348b65d79ed59f113996eed36711c5cb8d240fbebc7e',
    'nirepo/jupyter-scipy-ssh:latest': 'sha256:4831abb222b3ac6cdfa17b8d9a6efad10f5555cb5497548b201143e1218a923c',
    'nirepo/jupyter-spark-ssh:latest': 'sha256:0ea465a32d093670374ffd883a39b45d2835043a0fc5507ad68e4c3838b4242f',
    'nirepo/jupyter-tensorflow-ssh:latest': 'sha256:a11b46549c4dd26e06c8dd733d5ecfa1384211e6e0964c38420f5021fe5a9f6e',
}


def get_required_templates() -> list:
    """
    Get list of required custom template images.

    Note: This should be kept in sync with CUSTOM_TEMPLATE_IMAGES in miner's container.py

    Returns:
        list: List of required template image names
    """
    return list(TEMPLATE_EXPECTED_DIGESTS.keys())


def verify_template_images(images_list: list, hotkey: str = "") -> dict:
    """
    Verify which custom template images are available and validate their digests.

    Args:
        images_list (list): List of images from miner with {repository, tag, digest, full_name}
        hotkey (str): Hotkey for logging context

    Returns:
        dict: {
            "available_templates": list,
            "missing_templates": list,
            "invalid_digests": list,
            "templates_score": float,
            "total_templates": int,
            "docker_available": bool
        }
    """
    required_templates = get_required_templates()

    # Create a dict of available images by full_name
    available_images_dict = {}
    for img in images_list:
        full_name = img.get("full_name")
        if full_name:
            available_images_dict[full_name] = img.get("digest")

    bt.logging.trace(f"{hotkey}: Found {len(available_images_dict)} docker images on miner")

    # Check which required templates are available and have correct digests
    available_templates = []
    missing_templates = []
    invalid_digests = []

    for template in required_templates:
        expected_digest = TEMPLATE_EXPECTED_DIGESTS.get(template)
        actual_digest = available_images_dict.get(template)

        if actual_digest is None:
            # Template image not found
            missing_templates.append(template)
            bt.logging.trace(f"{hotkey}: ❌ Template missing: {template}")
        elif actual_digest != expected_digest:
            # Template found but digest doesn't match
            invalid_digests.append({
                "template": template,
                "expected": expected_digest,
                "actual": actual_digest
            })
            bt.logging.warning(
                f"{hotkey}: ⚠️ Template digest mismatch: {template}\n"
                f"  Expected: {expected_digest}\n"
                f"  Actual:   {actual_digest}"
            )
        else:
            # Template found and digest matches
            available_templates.append(template)
            bt.logging.trace(f"{hotkey}: ✅ Template available with correct digest: {template}")

    # Calculate score (only correctly verified templates count)
    templates_score = len(available_templates) / len(required_templates) if required_templates else 0.0

    bt.logging.info(
        f"{hotkey}: Template check - {len(available_templates)}/{len(required_templates)} "
        f"available with correct digests ({templates_score:.1%})"
    )

    if invalid_digests:
        bt.logging.warning(
            f"{hotkey}: Found {len(invalid_digests)} templates with invalid digests"
        )

    return {
        "available_templates": available_templates,
        "missing_templates": missing_templates,
        "invalid_digests": invalid_digests,
        "templates_score": templates_score,
        "total_templates": len(required_templates),
        "docker_available": bool(images_list)
    }


async def perform_template_check(
    wallet: bt.wallet,
    axon: bt.AxonInfo
) -> dict:
    """
    Performs template availability check via Allocate request with checking=True.

    Args:
        wallet: Wallet instance to create dendrite
        axon: Axon information of the miner

    Returns:
        dict: {
            "success": bool,
            "available_templates": list,
            "missing_templates": list,
            "invalid_digests": list,
            "templates_score": float,
            "total_templates": int,
            "docker_available": bool,
            "error_message": str | None
        }
    """
    hotkey = axon.hotkey

    try:
        bt.logging.debug(f"{hotkey}: Sending Allocate request with checking=True for template verification")

        async with bt.dendrite(wallet=wallet) as dendrite:
            response = await dendrite(
                axon,
                Allocate(
                    timeline=1,
                    device_requirement={},
                    checking=True
                ),
                timeout=30,
            )

        if not response:
            bt.logging.error(f"{hotkey}: No response from miner")
            return {
                "success": False,
                "available_templates": [],
                "missing_templates": get_required_templates(),
                "invalid_digests": [],
                "templates_score": 0.0,
                "total_templates": len(get_required_templates()),
                "docker_available": False,
                "error_message": "No response from miner"
            }

        output = response

        # Check docker_available status (whether Docker query succeeded)
        # Note: 'status' field indicates allocation availability, not query success
        if not output or not output.get("docker_available"):
            error_msg = output.get("message", "Unknown error") if output else "Empty response"
            bt.logging.error(f"{hotkey}: Miner error: {error_msg}")
            return {
                "success": False,
                "available_templates": [],
                "missing_templates": get_required_templates(),
                "invalid_digests": [],
                "templates_score": 0.0,
                "total_templates": len(get_required_templates()),
                "docker_available": False,
                "error_message": error_msg
            }

        # Get images list and verify
        images_list = output.get("images", [])
        template_result = verify_template_images(images_list, hotkey)

        # Success requires 100% templates with correct digests
        docker_available = template_result.get("docker_available", False)
        templates_score = template_result.get("templates_score", 0.0)
        invalid_digests = template_result.get("invalid_digests", [])
        success = docker_available and templates_score >= 1.0 and len(invalid_digests) == 0

        if success:
            bt.logging.success(
                f"✅ {hotkey}: All {template_result['total_templates']} templates verified with correct digests"
            )
        else:
            if template_result.get("missing_templates"):
                bt.logging.warning(f"{hotkey}: Missing templates: {template_result['missing_templates']}")
            if invalid_digests:
                bt.logging.warning(f"{hotkey}: {len(invalid_digests)} templates with invalid digests")

        return {
            "success": success,
            "available_templates": template_result["available_templates"],
            "missing_templates": template_result["missing_templates"],
            "invalid_digests": invalid_digests,
            "templates_score": template_result["templates_score"],
            "total_templates": template_result["total_templates"],
            "docker_available": docker_available,
            "error_message": None if success else (
                f"Missing {len(template_result.get('missing_templates', []))} templates, "
                f"{len(invalid_digests)} invalid digests"
            )
        }

    except Exception as e:
        bt.logging.error(f"{hotkey}: Template check error: {e}")
        return {
            "success": False,
            "available_templates": [],
            "missing_templates": get_required_templates(),
            "invalid_digests": [],
            "templates_score": 0.0,
            "total_templates": len(get_required_templates()),
            "docker_available": False,
            "error_message": str(e)
        }
