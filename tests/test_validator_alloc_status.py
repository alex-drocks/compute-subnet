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
async def test_validate_single_skips_when_allocated():
    validator = Validator.__new__(Validator)
    axon = SimpleNamespace(hotkey="hk-allocated", ip="127.0.0.1")

    async def _alloc_should_not_run(*_args, **_kwargs):
        raise AssertionError("allocate_miner should not run when miner is allocated")

    validator.allocate_miner = _alloc_should_not_run

    api_map = {axon.hotkey: [_make_instance(axon.hotkey, stats={"alloc_state": "allocated"})]}

    res = await validator._validate_single(axon, api_map)

    assert res["skipped"] is True
    assert res["skip_reason"] == "allocated"


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

    res = await validator._validate_single(axon, api_map)

    assert "skipped" not in res
    assert res["allocation_ok"] is False
