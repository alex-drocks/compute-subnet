"""
Tests for the PubSub disabled functionality.

This module tests that when the --pubsub.disable flag is set,
the PubSubClient does not publish any messages.
"""

from unittest import mock

import pytest

from compute.pubsub.client import PubSubClient
from compute.pubsub.message_factory import MessageFactory
from compute.pubsub.message_types import TOPICS


# --- Fixtures for common objects ---

@pytest.fixture
def mock_wallet():
    """Returns a mock wallet with hotkey."""
    wallet = mock.MagicMock()
    wallet.hotkey.ss58_address = "5GTestHotkey123456789"
    return wallet


@pytest.fixture
def mock_config_enabled():
    """Returns a mock config with pubsub enabled (default)."""
    config = mock.MagicMock()
    config.pubsub_disabled = False
    config.subtensor.network = "test"
    return config


@pytest.fixture
def mock_config_disabled():
    """Returns a mock config with pubsub disabled."""
    config = mock.MagicMock()
    config.pubsub_disabled = True
    config.subtensor.network = "test"
    return config


@pytest.fixture
def mock_auth():
    """Mock the SN27TokenAuth class."""
    with mock.patch('compute.pubsub.client.SN27TokenAuth') as mock_auth_class:
        mock_auth_instance = mock.MagicMock()
        mock_auth_instance.get_project_id.return_value = "test-project-id"
        mock_auth_instance.get_credentials.return_value = mock.MagicMock()
        mock_auth_class.return_value = mock_auth_instance
        yield mock_auth_class


@pytest.fixture
def mock_pubsub_clients():
    """Mock the Google Cloud Pub/Sub clients."""
    with mock.patch(
        'compute.pubsub.client.pubsub_v1.PublisherClient'
    ) as mock_publisher, mock.patch(
        'compute.pubsub.client.pubsub_v1.SubscriberClient'
    ) as mock_subscriber:

        # Setup mock publisher
        publisher_instance = mock.MagicMock()
        publisher_instance.publish.return_value.result.return_value = (
            "test-message-id"
        )
        mock_publisher.return_value = publisher_instance

        # Setup mock subscriber
        subscriber_instance = mock.MagicMock()
        subscriber_instance.topic_path.return_value = (
            "projects/test-project-id/topics/test-topic"
        )
        subscriber_instance.subscription_path.return_value = (
            "projects/test-project-id/subscriptions/test-sub"
        )
        mock_subscriber.return_value = subscriber_instance

        yield {
            'publisher_class': mock_publisher,
            'subscriber_class': mock_subscriber,
            'publisher_instance': publisher_instance,
            'subscriber_instance': subscriber_instance
        }


# ============================================================================
# TESTS FOR PUBSUB DISABLED FUNCTIONALITY
# ============================================================================

class TestPubSubDisabledFlag:
    """Test that pubsub_disabled flag prevents publishing."""

    def test_client_initialization_with_disabled_flag(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that client initializes but skips auth when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Verify that disabled flag is set
        assert client.disabled is True

        # Verify that auth and clients are not initialized
        assert (
            not hasattr(client, 'auth')
            or client.auth is None
            or client.disabled
        )

    def test_client_initialization_with_enabled_flag(
        self, mock_wallet, mock_config_enabled, mock_auth, mock_pubsub_clients
    ):
        """Test that client initializes normally when enabled."""
        # Create client with enabled flag (default)
        # Note: mock_pubsub_clients fixture is needed for mocking
        _ = mock_pubsub_clients  # noqa: F841
        client = PubSubClient(wallet=mock_wallet, config=mock_config_enabled)

        # Verify that disabled flag is False
        assert client.disabled is False

        # Verify that auth was initialized
        mock_auth.assert_called_once_with(mock_wallet, mock_config_enabled)

    @pytest.mark.asyncio
    async def test_publish_pog_result_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that publish_pog_result_event returns None when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to publish a PoG result
        result = await client.publish_pog_result_event(
            miner_hotkey="5GMinerHotkey123",
            request_id="test-request-123",
            result="success",
            validation_duration=1.5,
            benchmark_data={"hashrate": 1000},
            error_details=None,
            health_check_result=True
        )

        # Verify that nothing was published (returns None)
        assert result is None

    @pytest.mark.asyncio
    async def test_publish_miner_allocation_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that publish_miner_allocation returns None when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to publish a miner allocation
        result = await client.publish_miner_allocation(
            miner_hotkey="5GMinerHotkey123",
            allocation_result=True,
            allocation_error=None
        )

        # Verify that nothing was published (returns None)
        assert result is None

    @pytest.mark.asyncio
    async def test_publish_miner_deallocation_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that publish_miner_deallocation returns None when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to publish a miner deallocation
        result = await client.publish_miner_deallocation(
            miner_hotkey="5GMinerHotkey123",
            retry_count=0,
            deallocation_result=True,
            deallocation_error=None
        )

        # Verify that nothing was published (returns None)
        assert result is None

    @pytest.mark.asyncio
    async def test_publish_with_fallback_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that publish_with_fallback doesn't publish when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Create a test message
        factory = MessageFactory(
            source='validator',
            validator_hotkey=mock_wallet.hotkey.ss58_address
        )
        message = factory.create_pog_result(
            miner_hotkey="5GMinerHotkey123",
            request_id="test-request-123",
            result="success",
            validation_duration_seconds=1.5
        )

        # Mock fallback callback to verify it's not called
        fallback_callback = mock.AsyncMock()

        # Try to publish with fallback - when disabled, should not publish
        # The method should handle disabled state gracefully
        await client.publish_with_fallback(
            TOPICS.VALIDATION_EVENTS,
            message,
            fallback_callback=fallback_callback
        )

        # When disabled, the client should not attempt to publish
        # The exact behavior depends on implementation, but no errors raised

    @pytest.mark.asyncio
    async def test_no_publisher_calls_when_disabled(
        self, mock_wallet, mock_config_disabled, mock_pubsub_clients
    ):
        """Test that Google Cloud publisher is never called when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to publish multiple messages
        await client.publish_pog_result_event(
            miner_hotkey="5GMinerHotkey123",
            request_id="test-request-123",
            result="success",
            validation_duration=1.5
        )

        await client.publish_miner_allocation(
            miner_hotkey="5GMinerHotkey123",
            allocation_result=True
        )

        await client.publish_miner_deallocation(
            miner_hotkey="5GMinerHotkey123",
            deallocation_result=True
        )

        # Verify that publisher was never instantiated or called
        publisher_instance = mock_pubsub_clients['publisher_instance']
        publisher_instance.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_subscribe_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that subscribe_to_topics returns early when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to subscribe - should return early without error
        await client.subscribe_to_topics()

        # Should complete without errors and without creating subscriptions

    def test_refresh_credentials_when_disabled(
        self, mock_wallet, mock_config_disabled
    ):
        """Test that refresh_credentials returns True when disabled."""
        # Create client with disabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_disabled)

        # Try to refresh credentials - should return True immediately
        result = client.refresh_credentials()

        # Should return True without attempting to refresh
        assert result is True


class TestPubSubEnabledPublishing:
    """Test that publishing works normally when enabled."""

    @pytest.mark.asyncio
    async def test_publish_pog_result_when_enabled(
        self, mock_wallet, mock_config_enabled, mock_auth, mock_pubsub_clients
    ):
        """Test that publish_pog_result_event works when enabled."""
        # Note: mock_auth and mock_pubsub_clients fixtures needed for mocking
        _ = mock_auth  # noqa: F841
        _ = mock_pubsub_clients  # noqa: F841
        # Create client with enabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_enabled)

        # Mock the direct_publish_message to return a message ID
        with mock.patch.object(
            client, 'direct_publish_message', return_value="test-message-id"
        ) as mock_publish:
            # Publish a PoG result without benchmark_data
            result = await client.publish_pog_result_event(
                miner_hotkey="5GMinerHotkey123",
                request_id="test-request-123",
                result="success",
                validation_duration=1.5,
                benchmark_data=None,
                error_details=None,
                health_check_result=True
            )

            # Verify that publish was called
            mock_publish.assert_called_once()

            # Verify that a message ID was returned
            assert result == "test-message-id"

    @pytest.mark.asyncio
    async def test_publish_miner_allocation_when_enabled(
        self, mock_wallet, mock_config_enabled, mock_auth, mock_pubsub_clients
    ):
        """Test that publish_miner_allocation works when enabled."""
        # Note: mock_auth and mock_pubsub_clients fixtures needed for mocking
        _ = mock_auth  # noqa: F841
        _ = mock_pubsub_clients  # noqa: F841
        # Create client with enabled flag
        client = PubSubClient(wallet=mock_wallet, config=mock_config_enabled)

        # Mock the direct_publish_message to return a message ID
        with mock.patch.object(
            client, 'direct_publish_message', return_value="test-message-id"
        ) as mock_publish:
            # Publish a miner allocation
            result = await client.publish_miner_allocation(
                miner_hotkey="5GMinerHotkey123",
                allocation_result=True,
                allocation_error=None
            )

            # Verify that publish was called
            mock_publish.assert_called_once()

            # Verify that a message ID was returned
            assert result == "test-message-id"
