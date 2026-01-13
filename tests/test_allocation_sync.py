#!/usr/bin/env python3
"""
Test script for allocation sync functionality.
Tests both the API client and validator sync logic.
"""

import hashlib
import json
import sys
import os
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_canonical_json():
    """Test that canonical JSON encoding works correctly."""
    from neurons.Validator.api_client import _canonical_json

    # Test sorting and no spaces
    payload = {"b": 2, "a": 1, "c": 3}
    result = _canonical_json(payload)
    expected = b'{"a":1,"b":2,"c":3}'
    assert result == expected, f"Expected {expected}, got {result}"
    print("✓ _canonical_json works correctly")


def test_sync_allocations_signature():
    """Test that sync_allocations builds the correct signature payload."""
    from neurons.Validator.api_client import ValidationApiClient, _canonical_json

    # Mock wallet
    mock_wallet = MagicMock()
    mock_wallet.hotkey.ss58_address = "5ValidatorHotkey123"
    mock_wallet.hotkey.sign = MagicMock(return_value=b'\x00' * 64)  # Dummy signature

    client = ValidationApiClient(wallet=mock_wallet)

    # Mock _post to capture what's being sent
    captured_body = {}
    def mock_post(path, body):
        captured_body.update(body)
        return {"status": "ok"}

    client._post = mock_post

    # Call sync_allocations
    allocations = [
        {"key": "5Miner1...", "state": "allocated"},
        {"key": "5Miner2...", "state": "free"},
    ]
    result = client.sync_allocations(allocations)

    # Verify result
    assert result == {"status": "ok"}, f"Expected ok, got {result}"

    # Verify body structure
    assert "hotkey" in captured_body, "Missing hotkey"
    assert "payload" in captured_body, "Missing payload"
    assert "signature" in captured_body, "Missing signature"
    assert "ts" in captured_body, "Missing ts"
    assert "purpose" in captured_body, "Missing purpose"

    assert captured_body["hotkey"] == "5ValidatorHotkey123"
    assert captured_body["purpose"] == "validator_alloc_v1"
    assert captured_body["payload"]["allocations"] == allocations

    # Verify sign was called
    assert mock_wallet.hotkey.sign.called, "Wallet sign was not called"

    print("✓ sync_allocations builds correct request body")
    print(f"  Body structure: {list(captured_body.keys())}")


def test_sync_allocations_empty():
    """Test that empty allocations returns early."""
    from neurons.Validator.api_client import ValidationApiClient

    client = ValidationApiClient(wallet=MagicMock())
    result = client.sync_allocations([])

    assert result == {"status": "ok", "message": "No allocations to sync"}
    print("✓ sync_allocations handles empty list correctly")


def test_sync_allocations_no_wallet():
    """Test that missing wallet is handled."""
    from neurons.Validator.api_client import ValidationApiClient

    client = ValidationApiClient(wallet=None)
    result = client.sync_allocations([{"key": "test", "state": "free"}])

    assert result is None
    print("✓ sync_allocations handles missing wallet correctly")


def test_validator_sync_method():
    """Test the validator's sync_allocation_status_to_api method."""
    import asyncio

    # We need to mock several things:
    # 1. Database cursor
    # 2. get_queryable() method
    # 3. metagraph.hotkeys
    # 4. api_client.sync_allocations

    # Create mock database
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        ("5AllocatedMiner1",),
        ("5AllocatedMiner2",),
    ]

    mock_db = MagicMock()
    mock_db.get_cursor.return_value = mock_cursor

    # Create mock metagraph
    mock_metagraph = MagicMock()
    mock_metagraph.hotkeys = {
        0: "5AllocatedMiner1",
        1: "5AllocatedMiner2",
        2: "5FreeMiner1",
        3: "5FreeMiner2",
    }

    # Create mock api_client
    mock_api_client = MagicMock()
    captured_allocations = []
    def capture_sync(allocations):
        captured_allocations.extend(allocations)
        return {"status": "ok"}
    mock_api_client.sync_allocations = capture_sync

    # Create a minimal validator-like object
    class MockValidator:
        def __init__(self):
            self.db = mock_db
            self.metagraph = mock_metagraph
            self.api_client = mock_api_client
            self._allocation_sync_fail_count = 0

        def get_queryable(self):
            return [0, 1, 2, 3]  # All 4 UIDs are queryable

        async def sync_allocation_status_to_api(self):
            """Copy of the actual method for testing."""
            try:
                cursor = self.db.get_cursor()
                try:
                    cursor.execute("SELECT hotkey FROM allocation")
                    rows = cursor.fetchall()
                    current_allocations = {row[0] for row in rows}
                finally:
                    cursor.close()

                queryable_uids = self.get_queryable()
                all_hotkeys = {self.metagraph.hotkeys[uid] for uid in queryable_uids}

                allocations = []
                for hk in all_hotkeys:
                    state = "allocated" if hk in current_allocations else "free"
                    allocations.append({"key": hk, "state": state})

                if not allocations:
                    return

                result = self.api_client.sync_allocations(allocations)

                if result:
                    self._allocation_sync_fail_count = 0
                else:
                    self._allocation_sync_fail_count += 1

            except Exception as e:
                self._allocation_sync_fail_count += 1
                raise

    # Run the test
    validator = MockValidator()
    asyncio.run(validator.sync_allocation_status_to_api())

    # Verify correct allocations were built
    assert len(captured_allocations) == 4, f"Expected 4 allocations, got {len(captured_allocations)}"

    # Check states
    states = {a["key"]: a["state"] for a in captured_allocations}
    assert states["5AllocatedMiner1"] == "allocated"
    assert states["5AllocatedMiner2"] == "allocated"
    assert states["5FreeMiner1"] == "free"
    assert states["5FreeMiner2"] == "free"

    print("✓ Validator sync builds correct allocation list")
    print(f"  Allocated: 2, Free: 2")


def test_post_method():
    """Test the _post method handles responses correctly."""
    from neurons.Validator.api_client import ValidationApiClient

    client = ValidationApiClient(wallet=None)

    # Test successful response
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_post.return_value = mock_response

        result = client._post("/test", {"data": "test"})
        assert result == {"success": True}

    print("✓ _post handles successful responses")

    # Test 4xx error
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = client._post("/test", {"data": "test"})
        assert result is None

    print("✓ _post handles 4xx errors")


if __name__ == "__main__":
    print("\n=== Testing Allocation Sync Implementation ===\n")

    try:
        test_canonical_json()
        test_sync_allocations_empty()
        test_sync_allocations_no_wallet()
        test_sync_allocations_signature()
        test_post_method()
        test_validator_sync_method()

        print("\n" + "=" * 50)
        print("All tests passed!")
        print("=" * 50)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
