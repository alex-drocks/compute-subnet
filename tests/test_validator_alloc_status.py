import pytest
from types import SimpleNamespace

from neurons.validator import Validator
from neurons.Validator.api_client import ApiInstance
import neurons.validator as validator_module


def _make_instance(hotkey: str, status: str = "pass", stats: dict | None = None) -> ApiInstance:
    return ApiInstance(
        inst_uuid="inst-1",
        pk_M=hotkey,
        current_status=status,
        hardware={"gpus": [{"uuid": "gpu-1", "name": "A100"}]},
        stats=stats or {},
    )


@pytest.mark.asyncio
async def test_validate_single_validates_allocated_miners():
    """PoGv3 validates all miners via test containers regardless of allocation state."""
    validator = Validator.__new__(Validator)
    validator.ssh_public_key = "ssh-key"
    axon = SimpleNamespace(hotkey="hk-allocated", ip="127.0.0.1")

    # Mock allocation to return None (simulating test container allocation attempt)
    async def _alloc_mock(*_args, **_kwargs):
        return None

    validator.allocate_miner = _alloc_mock

    api_map = {axon.hotkey: [_make_instance(axon.hotkey, stats={"alloc_state": "allocated"})]}

    mock_dendrite = SimpleNamespace()
    res = await validator._validate_single(axon, api_map, mock_dendrite)

    # PoGv3 doesn't skip allocated miners - it validates via test containers
    assert "skipped" not in res
    assert res["alloc_state"] == "allocated"
    assert res["allocation_ok"] is False  # Mock returned None


@pytest.mark.asyncio
async def test_validate_single_rechecks_allocation_after_failure(monkeypatch):
    validator = Validator.__new__(Validator)
    validator.ssh_public_key = "ssh-key"

    async def _alloc_fail(*_args, **_kwargs):
        return None

    validator.allocate_miner = _alloc_fail

    monkeypatch.setattr(
        validator_module.rsa,
        "generate_key_pair",
        lambda: ("priv", "pub"),
    )

    axon = SimpleNamespace(hotkey="hk-fail", ip="127.0.0.1")
    api_map = {axon.hotkey: [_make_instance(axon.hotkey)]}

    mock_dendrite = SimpleNamespace()
    res = await validator._validate_single(axon, api_map, mock_dendrite)

    assert "skipped" not in res
    assert res["allocation_ok"] is False
