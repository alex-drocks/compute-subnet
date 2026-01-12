"""
Test GPU weight redistribution algorithm.

Verifies that miner emission is distributed only among active GPU types,
not burned when some configured GPU types are absent from the network.
"""
import pytest


def calculate_gpu_weights(
    gpu_priorities: dict,
    gpu_groups: dict,
    uid_to_score: dict,
    total_miner_emission: float,
    num_uids: int,
) -> tuple[list, float, dict]:
    """
    Extracted GPU weight calculation logic for testing.

    This mirrors the logic in Validator.set_weights() at neurons/validator.py:1537-1565

    Args:
        gpu_priorities: Map of GPU name -> priority weight from config
        gpu_groups: Map of GPU name -> list of UIDs with that GPU (active GPUs)
        uid_to_score: Map of UID -> score (0.0-1.0)
        total_miner_emission: Total emission allocated to miners (e.g., 0.05 = 5%)
        num_uids: Total number of UIDs on the subnet

    Returns:
        (uid_weights list, total_assigned_weight, gpu_actual_emission dict)
    """
    # Key fix: sum only ACTIVE GPU priorities, not ALL configured priorities
    total_priority = sum(gpu_priorities.get(gpu_name, 0) for gpu_name in gpu_groups.keys())

    if total_priority == 0:
        return [0.0] * num_uids, 0.0, {}

    uid_weights = [0.0] * num_uids
    total_assigned_weight = 0.0
    gpu_actual_emission = {}

    for gpu_name, uids in gpu_groups.items():
        priority = gpu_priorities[gpu_name]
        group_cap = (priority / total_priority) * total_miner_emission

        scores = [uid_to_score[uid] for uid in uids]
        scores_sum = sum(scores)
        if scores_sum == 0:
            continue

        normalized = [s / scores_sum for s in scores]
        capped = [n * group_cap for n in normalized]

        for i, uid in enumerate(uids):
            uid_weights[uid] = capped[i]

        gpu_actual_emission[gpu_name] = group_cap
        total_assigned_weight += group_cap

    return uid_weights, total_assigned_weight, gpu_actual_emission


class TestGpuWeightRedistribution:
    """Test that GPU weights redistribute all emission to active miners."""

    # GPU priorities matching config.yaml (market-aligned + 20% consumer bonus)
    GPU_PRIORITIES = {
        # Enterprise tier
        "NVIDIA B200": 12,
        "NVIDIA H200": 10,
        "NVIDIA H200 NVL": 9,
        "NVIDIA H100 80GB HBM3": 10,
        "NVIDIA H100 PCIe": 9,
        "NVIDIA H100 NVL": 8,
        # Datacenter tier
        "NVIDIA A100-SXM4-80GB": 4,
        "NVIDIA A100 80GB PCIe": 4,
        "NVIDIA L40S": 3,
        "NVIDIA L40": 2.5,
        "NVIDIA A40": 2,
        # Prosumer tier
        "NVIDIA RTX 6000 Ada Generation": 2,
        "NVIDIA RTX A6000": 1.5,
        "NVIDIA RTX A5000": 1.2,
        "NVIDIA RTX A4500": 1.2,
        "NVIDIA RTX 4000 Ada Generation": 1,
        "NVIDIA RTX A4000": 1,
        # Consumer tier (+20% decentralization bonus)
        "NVIDIA GeForce RTX 5090": 1.8,
        "NVIDIA GeForce RTX 4090": 1.2,
        "NVIDIA GeForce RTX 4080 SUPER": 1,
        "NVIDIA GeForce RTX 4080": 1,
        "NVIDIA GeForce RTX 3090": 0.85,
        "NVIDIA L4": 0.6,
    }

    def test_single_rtx4090_gets_full_emission(self):
        """When only RTX 4090 exists, it should get the full miner emission."""
        total_miner_emission = 0.05  # 5%

        # Only RTX 4090 is active (priority=1)
        gpu_groups = {"NVIDIA GeForce RTX 4090": [0]}
        uid_to_score = {0: 1.0}  # Full score

        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        # RTX 4090 should get full 5%, not 0.033% (1/151 * 5%)
        assert abs(total_assigned - total_miner_emission) < 1e-6, \
            f"Expected {total_miner_emission}, got {total_assigned}"
        assert abs(weights[0] - total_miner_emission) < 1e-6
        assert abs(gpu_emission["NVIDIA GeForce RTX 4090"] - total_miner_emission) < 1e-6

    def test_single_rtx3090_gets_full_emission(self):
        """When only RTX 3090 exists (priority=0.5), it should get full miner emission."""
        total_miner_emission = 0.05

        gpu_groups = {"NVIDIA GeForce RTX 3090": [0, 1]}
        uid_to_score = {0: 0.8, 1: 0.2}  # 80/20 split

        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        # Full 5% should be distributed
        assert abs(total_assigned - total_miner_emission) < 1e-6
        # Check proportional split: 80% and 20% of 5%
        assert abs(weights[0] - 0.04) < 1e-6  # 80% of 5%
        assert abs(weights[1] - 0.01) < 1e-6  # 20% of 5%

    def test_mixed_gpus_preserve_ratios(self):
        """When multiple GPU types exist, priority ratios should be preserved."""
        total_miner_emission = 0.05

        # H100 (priority=10) and RTX 4090 (priority=1.2) both active
        gpu_groups = {
            "NVIDIA H100 80GB HBM3": [0],
            "NVIDIA GeForce RTX 4090": [1],
        }
        uid_to_score = {0: 1.0, 1: 1.0}  # Both full score

        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        # Total should still be 5%
        assert abs(total_assigned - total_miner_emission) < 1e-6

        # Check ratios: H100 gets 10/(10+1.2) of 5%, RTX 4090 gets 1.2/(10+1.2) of 5%
        total_active_priority = 10 + 1.2
        expected_h100 = (10 / total_active_priority) * total_miner_emission
        expected_4090 = (1.2 / total_active_priority) * total_miner_emission

        assert abs(gpu_emission["NVIDIA H100 80GB HBM3"] - expected_h100) < 1e-6
        assert abs(gpu_emission["NVIDIA GeForce RTX 4090"] - expected_4090) < 1e-6

        # H100 should earn ~8.33x more than RTX 4090 (10/1.2)
        expected_ratio = 10 / 1.2
        ratio = weights[0] / weights[1]
        assert abs(ratio - expected_ratio) < 1e-4, f"Expected ratio {expected_ratio}, got {ratio}"

    def test_all_configured_gpus_active(self):
        """When all GPU types are active, behavior matches original algorithm."""
        total_miner_emission = 0.05

        # All GPUs active with one miner each
        gpu_groups = {name: [i] for i, name in enumerate(self.GPU_PRIORITIES.keys())}
        uid_to_score = {i: 1.0 for i in range(len(self.GPU_PRIORITIES))}

        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        # Total should be full 5%
        assert abs(total_assigned - total_miner_emission) < 1e-6

        # Sum of all priorities
        total_priority = sum(v for v in self.GPU_PRIORITIES.values() if v > 0)

        # Each GPU should get its proportional share
        for gpu_name, priority in self.GPU_PRIORITIES.items():
            expected = (priority / total_priority) * total_miner_emission
            assert abs(gpu_emission[gpu_name] - expected) < 1e-6

    def test_zero_score_miners_excluded(self):
        """Miners with zero score should not receive emission."""
        total_miner_emission = 0.05

        gpu_groups = {"NVIDIA GeForce RTX 4090": [0, 1, 2]}
        uid_to_score = {0: 0.5, 1: 0.0, 2: 0.5}  # Middle miner has zero score

        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        assert weights[1] == 0.0  # Zero score = zero weight
        assert abs(weights[0] - 0.025) < 1e-6  # 50% of 5%
        assert abs(weights[2] - 0.025) < 1e-6  # 50% of 5%

    def test_empty_gpu_groups_returns_zero(self):
        """When no active GPUs, total assigned should be zero."""
        weights, total_assigned, gpu_emission = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups={},
            uid_to_score={},
            total_miner_emission=0.05,
            num_uids=256,
        )

        assert total_assigned == 0.0
        assert sum(weights) == 0.0
        assert gpu_emission == {}

    def test_old_algorithm_would_fail(self):
        """
        Demonstrate that the OLD algorithm would give wrong results.

        OLD: total_priority = sum(ALL config priorities)
        NEW: total_priority = sum(ACTIVE priorities only)
        """
        total_miner_emission = 0.05
        gpu_groups = {"NVIDIA GeForce RTX 4090": [0]}
        uid_to_score = {0: 1.0}

        # Calculate what OLD algorithm would give
        old_total_priority = sum(v for v in self.GPU_PRIORITIES.values() if v > 0)
        rtx4090_priority = self.GPU_PRIORITIES["NVIDIA GeForce RTX 4090"]  # 1.2
        old_weight = (rtx4090_priority / old_total_priority) * total_miner_emission

        # Calculate what NEW algorithm gives
        weights, total_assigned, _ = calculate_gpu_weights(
            self.GPU_PRIORITIES,
            gpu_groups,
            uid_to_score,
            total_miner_emission,
            num_uids=256,
        )

        # OLD would give a small fraction, NEW gives full 5%
        assert old_weight < 0.002  # Old algorithm: small fraction
        assert total_assigned > 0.049  # New algorithm: ~5%
        assert total_assigned / old_weight > 25  # New is significantly better
