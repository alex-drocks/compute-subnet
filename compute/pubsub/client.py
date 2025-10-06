"""
SN27 Pub/Sub client for Pub/Sub related communication at SN27.

This module provides a specialized client for validators using the
SN27 token gateway authentication flow.
"""

import asyncio
import json
import logging
import time
from typing import Callable
from google.cloud import pubsub_v1
from google.api_core import exceptions as gcp_exceptions
from google.api_core.retry import Retry

from .auth import SN27TokenAuth
from .message_types import PubSubMessage, TOPICS
from .message_factory import MessageFactory
from .exceptions import AuthenticationError, ConfigurationError, PublishError


class PubSubClient:
    """
    Pub/Sub client for validators using SN27 token gateway authentication.

    This client provides both publishing and subscription capabilities
    for validators communicating with the SN27 backend.
    """

    def __init__(
        self,
        wallet,
        config,
        timeout: float = 30.0,
        auto_refresh_interval: int = 600  # 30 minutes in blocks (assuming 3s blocks)
    ):
        """
        Initialize the validator gateway pub/sub client.

        Args:
            wallet: Bittensor wallet instance
            config: Validator config
            timeout: Timeout for publish operations
            auto_refresh_interval: Blocks between token refresh (0 to disable)
        """
        self.wallet = wallet
        self.config = config
        self.timeout = timeout
        self.auto_refresh_interval = auto_refresh_interval
        self.logger = logging.getLogger(__name__)

        # Check if pubsub is disabled
        self.disabled = getattr(config, 'pubsub_disabled', False)
        if self.disabled:
            self.logger.info("PubSub functionality disabled via --pubsub.disable flag")
            return

        # Initialize authentication
        if not wallet or not config:
            raise ConfigurationError("wallet and config are required for token gateway authentication")

        # Initialize auth provider
        self.auth = SN27TokenAuth(wallet, config)

        # Initialize clients
        self.publisher: pubsub_v1.PublisherClient | None = None
        self.subscriber: pubsub_v1.SubscriberClient | None = None

        # Subscription management
        self.subscription_futures: dict = {}
        self._message_callbacks: dict = {}

        # Message queues for reliable publishing
        self.queues = {
            TOPICS.ALLOCATION_EVENTS: asyncio.Queue(),
            TOPICS.MINER_EVENTS: asyncio.Queue(),
            TOPICS.SYSTEM_EVENTS: asyncio.Queue(),
            TOPICS.VALIDATION_EVENTS: asyncio.Queue(),
        }

        # Background workers for processing queues
        self._queue_workers: dict[str, asyncio.Task] = {}
        self._worker_shutdown = asyncio.Event()

        self.project_id = self.auth.get_project_id()

        # Initialize clients with retries
        try:
            self._initialize_clients()
        except AuthenticationError as e:
            self.logger.error(f"Failed to initialize Pub/Sub client: {e}")
            self.logger.warning("Pub/Sub client will retry authentication when first message is published")
            # Don't raise - allow the client to be created and retry later
            self.publisher = None
            self.subscriber = None
            # Keep topic paths - they don't require authentication

        # Initialize message factory for high-level methods
        self._message_factory = MessageFactory(
            source='validator', validator_hotkey=self.wallet.hotkey.ss58_address)

        # Start background queue workers
        self._start_queue_workers()

    def _initialize_clients(self, max_retries: int = 3):
        """Initialize publisher and subscriber clients with retry logic."""
        last_error = None

        for attempt in range(max_retries):
            try:
                credentials = self.auth.get_credentials()

                # Initialize clients
                self.publisher = pubsub_v1.PublisherClient(credentials=credentials)
                self.subscriber = pubsub_v1.SubscriberClient(credentials=credentials)

                self.logger.info("Successfully initialized Validator Gateway Pub/Sub client")
                return

            except Exception as e:
                last_error = e
                self.logger.warning(
                    f"Failed to initialize Pub/Sub client (attempt {attempt + 1}/{max_retries}): {e}",
                )

                if attempt < max_retries - 1:
                    # Exponential backoff: 2, 4, 8 seconds
                    backoff_time = 2 ** attempt
                    self.logger.info(f"Retrying in {backoff_time} seconds...")
                    time.sleep(backoff_time)

        # All retries failed
        raise AuthenticationError(
            f"Failed to initialize Pub/Sub client after {max_retries} attempts. Last error: {last_error}"
        )

    def refresh_credentials(self, max_retries: int = 5) -> bool:
        """
        Refresh authentication tokens and reinitialize clients with retry logic.

        Returns:
            True if successful, False if all retries failed
        """
        if self.disabled:
            return True

        last_error = None

        for attempt in range(max_retries):
            try:
                self.auth.refresh_tokens()
                self._initialize_clients(max_retries=1)  # Don't double-retry initialization
                self.logger.info("Successfully refreshed Pub/Sub credentials")
                return True

            except Exception as e:
                last_error = e
                self.logger.warning(
                    f"Failed to refresh credentials (attempt {attempt + 1}/{max_retries}): {e}",
                )

                if attempt < max_retries - 1:
                    # Exponential backoff: 2, 4, 8 seconds
                    backoff_time = 2 ** attempt
                    self.logger.info(f"Retrying credential refresh in {backoff_time} seconds...")
                    time.sleep(backoff_time)

        # All retries failed
        self.logger.error(
            f"Failed to refresh credentials after {max_retries} attempts. Last error: {last_error}",
        )
        return False

    def _start_queue_workers(self):
        """Start background workers to process message queues."""
        try:
            asyncio.get_running_loop()
            # We're in an async context, create tasks
            for topic_name in self.queues:
                worker = asyncio.create_task(self._queue_worker(topic_name))
                self._queue_workers[topic_name] = worker
                self.logger.info(f"Started queue worker for {topic_name}")
        except RuntimeError:
            # No running loop, workers will start when first message is queued
            self.logger.debug("No running event loop, queue workers will start when needed")

    async def _ensure_workers_started(self):
        """Ensure queue workers are started."""
        if not self._queue_workers:
            for topic_name in self.queues:
                worker = asyncio.create_task(self._queue_worker(topic_name))
                self._queue_workers[topic_name] = worker

    async def _queue_worker(self, topic_name: str):
        """Background worker to process messages from a queue."""
        queue = self.queues[topic_name]

        while not self._worker_shutdown.is_set():
            try:
                message_data = await asyncio.wait_for(queue.get(), timeout=1.0)

                # Try to publish with retry
                if await self._publish_with_retry(topic_name, message_data):
                    queue.task_done()
                else:
                    # Put back and wait before retry
                    await queue.put(message_data)
                    queue.task_done()
                    await asyncio.sleep(5.0)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in queue worker for {topic_name}: {e}")
                await asyncio.sleep(1.0)

    def _ensure_clients_initialized(self) -> bool:
        """Ensure clients are initialized, retry if needed."""
        # Check if we have both publisher and subscriber
        if self.publisher and self.subscriber:
            return True

        self.logger.info("Pub/Sub clients not initialized, attempting to initialize...")
        try:
            self._initialize_clients()
            return True
        except AuthenticationError as e:
            self.logger.error(f"Failed to initialize clients: {e}")
            return False

    async def _publish_with_retry(self, topic_name: str, message_data: bytes) -> bool:
        """Publish message with retry and token refresh."""
        # Ensure clients are initialized
        if not self._ensure_clients_initialized():
            return False

        if topic_name not in self.queues:
            self.logger.error(f"Topic {topic_name} not found in topic paths")
            return False
        topic_path = self.subscriber.topic_path(self.project_id, topic_name)
        for attempt in range(3):
            try:
                future = self.publisher.publish(topic_path, message_data)
                future.result(timeout=self.timeout)
                return True

            except gcp_exceptions.Unauthenticated:
                self.logger.warning(f"Token expired for {topic_name}, refreshing credentials...")

                # Try to refresh credentials with retries
                if self.refresh_credentials():
                    # Credentials refreshed successfully, retry the publish
                    continue
                else:
                    # Credential refresh failed after retries
                    self.logger.error(f"Cannot publish to {topic_name}: credential refresh failed")
                    return False

            except Exception as e:
                self.logger.error(f"Publish to {topic_name} failed (attempt {attempt + 1}): {e}")
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)

        return False

    async def _publish_message(self, topic_name: str, message: PubSubMessage) -> str:
        """Queue a message for publishing."""
        if topic_name not in self.queues:
            raise ConfigurationError(f"Unknown topic: {topic_name}")

        # Ensure workers are started
        await self._ensure_workers_started()

        # Queue the message
        message_data = json.dumps(message.to_dict()).encode("utf-8")
        await self.queues[topic_name].put(message_data)

        return f"queued-{int(time.time() * 1000)}"

    async def publish_pog_result_event(
        self,
        miner_hotkey: str,
        request_id: str,
        result: str,
        validation_duration: float,
        benchmark_data: dict = None,
        error_details: str = None,
        health_check_result: bool = None,
    ) -> str | None:
        """
        High-level method to publish PoG validation result with error handling.

        Args:
            miner_hotkey: The validated miner's hotkey
            request_id: The PoG request ID
            result: Validation result ("success", "failure", "timeout", "error")
            validation_duration: Duration of validation in seconds
            benchmark_data: Optional benchmark data dict
            error_details: Optional error details if result was error/failure

        Returns:
            Message ID or queued ID
        """
        if self.disabled:
            return None

        try:
            # Create PoG result message
            message = self._message_factory.create_pog_result(
                miner_hotkey=miner_hotkey,
                request_id=request_id,
                result=result,
                validation_duration_seconds=validation_duration,
                benchmark_data=benchmark_data,
                error_details=error_details,
                health_check_result=health_check_result
            )

            # Publish to validation events topic
            return await self.publish_to_validation_events(message)

        except Exception as e:
            self.logger.error(f"Failed to publish PoG result: {e}")
        return None

    async def publish_miner_allocation(
        self,
        miner_hotkey: str,
        allocation_result: bool | None = None,
        allocation_error: str | None = None,
    ) -> str | None:
        """
        High-level method to publish Miner allocation result with error handling.

        Args:
            miner_hotkey: The validated miner's hotkey
            allocation_result: Optional miner allocation result
            allocation_error: Optional miner allocation error

        Returns:
            Message ID or queued ID
        """
        if self.disabled:
            return None

        try:
            # Create Miner allocation result message
            message = self._message_factory.create_miner_allocation(
                miner_hotkey=miner_hotkey,
                allocation_result=allocation_result,
                allocation_error=allocation_error,
            )

            # Publish to miner events topic
            return await self.publish_to_miner_events(message)

        except Exception as e:
            self.logger.error(f"Failed to publish Miner allocation result: {e}")
        return None

    async def publish_miner_deallocation(
        self,
        miner_hotkey: str,
        retry_count: int | None = None,
        deallocation_result: bool | None = None,
        deallocation_error: str | None = None,
    ) -> str | None:
        """
        High-level method to publish Miner deallocation result with error handling.

        Args:
            miner_hotkey: The validated miner's hotkey
            retry_count: Optional retry count
            deallocation_result: Optional miner deallocation result
            deallocation_error: Optional miner deallocation error

        Returns:
            Message ID or queued ID
        """
        if self.disabled:
            return None

        try:
            # Create Miner deallocation result message
            message = self._message_factory.create_miner_deallocation(
                miner_hotkey=miner_hotkey,
                retry_count=retry_count,
                deallocation_result=deallocation_result,
                deallocation_error=deallocation_error,
            )

            # Publish to miner events topic
            return await self.publish_to_miner_events(message)

        except Exception as e:
            self.logger.error(f"Failed to publish Miner deallocation result: {e}")
        return None

    async def _publish(
        self,
        topic_name: str,
        topic_path: str,
        timeout: int,
        message: PubSubMessage,
        should_retry: bool = True,
        **kwargs,
    ) -> str:
        try:
            # Publish message
            future = self.publisher.publish(topic_path, timeout=timeout, **kwargs)

            # Wait for publish to complete
            message_id = await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=timeout
            )

            self.logger.info(
                f"Published {message.message_type} message to {topic_name} with ID: {message_id}"
            )
            return message_id
        except gcp_exceptions.Unauthenticated as e:
            self.logger.warning(f"Token expired for {topic_name}, refreshing credentials...")
            # Try to refresh credentials with retries
            if should_retry and self.refresh_credentials():
                # Credentials refreshed successfully, retry the publish
                return await self._publish(
                    topic_name,
                    topic_path,
                    timeout,
                    message,
                    should_retry=False,
                    **kwargs,
                )
            # Credential refresh failed after retries
            raise e

    async def direct_publish_message(
        self,
        topic_name: str,
        message: PubSubMessage,
        timeout: int
    ) -> str:
        """
        Publish a message to the specified topic.

        Args:
            topic_name: Name of the topic to publish to
            message: Message to publish

        Returns:
            Message ID of the published message
        """

        if topic_name not in self.queues:
            raise ConfigurationError(f"Unknown topic: {topic_name}")

        topic_path = self.subscriber.topic_path(self.project_id, topic_name)
        try:
            # Convert message to JSON
            message_data = json.dumps(message.to_dict()).encode('utf-8')

            # Prepare message attributes
            attributes = {
                'message_type': message.message_type,
                'timestamp': message.timestamp,
                'source': message.source,
            }
            if message.priority and message.priority != 'normal':
                attributes['priority'] = message.priority
            if message.correlation_id:
                attributes['correlation_id'] = message.correlation_id
            # this is 5 retries. 0, 1, 3, 7, 15
            retry = Retry(
                initial=1.0,     # delay before first retry
                multiplier=2.0,  # exponential backoff factor
                maximum=10.0,    # max delay between retries
                deadline=20.0    # total time allowed for all retries
            )
            # Wait for publish to complete
            message_id = await self._publish(
                topic_name,
                topic_path,
                timeout or self.timeout,
                message,
                data=message_data,
                retry=retry,
                **attributes
            )

            self.logger.info(
                f"Published {message.message_type} message to {topic_name} with ID: {message_id}"
            )
            return message_id

        except Exception as e:
            self.logger.error(f"Failed to publish message to {topic_name}: {e}")
            raise PublishError(f"Failed to publish message to {topic_name}: {e}") from e

    async def publish_with_fallback(
        self,
        topic_name: str,
        message: PubSubMessage,
        fallback_callback: Callable | None = None,
        acknowledgment_timeout: float | None = None,
        async_result: bool | None = False
    ) -> dict:
        """
        Publish a message with acknowledgment monitoring and webhook fallback.

        This method implements the primary pubsub approach with webhook fallback:
        1. Attempts to publish to PubSub
        2. If publish succeeds, monitors for acknowledgment within timeout
        3. If acknowledgment timeout occurs, triggers webhook fallback
        4. If publish fails, immediately triggers webhook fallback

        Args:
            topic_name: Name of the topic to publish to
            message: Message to publish
            fallback_callback: Function to call if PubSub fails or times out
            monitor_acknowledgment: Whether to monitor acknowledgment (default: True)
            acknowledgment_timeout: Override default acknowledgment timeout

        Returns:
            Dict with status and details
        """
        ack_timeout = acknowledgment_timeout or self.timeout

        try:
            # Step 1: Attempt to publish to PubSub
            self.logger.info(
                f"Publishing message to {topic_name} (publish_timeout={self.timeout}s)"
            )
            if async_result:
                return await self._publish_message(topic_name, message)
            else:
                return await self.direct_publish_message(topic_name, message, ack_timeout)

        except Exception as e:
            # Publish failed: Trigger immediate fallback
            self.logger.warning(f"PubSub publish failed: {e}, triggering immediate fallback")

            if fallback_callback:
                try:
                    return await fallback_callback()
                except Exception as fce:
                    self.logger.warning(f"PubSub publish fallback failed: {fce}")
            return None

    # Topic-specific publish methods with acknowledgment monitoring
    async def publish_to_allocation_events(
        self,
        message: PubSubMessage,
        fallback_callback: Callable | None = None,
        acknowledgment_timeout: float | None = None,
        async_result: bool | None = False
    ) -> dict:
        """Publish to allocation-events topic with acknowledgment monitoring."""
        return await self.publish_with_fallback(
            TOPICS.ALLOCATION_EVENTS,
            message,
            fallback_callback,
            acknowledgment_timeout,
            async_result
        )

    async def publish_to_miner_events(
        self,
        message: PubSubMessage,
        fallback_callback: Callable | None = None,
        acknowledgment_timeout: float | None = None,
        async_result: bool | None = False
    ) -> dict:
        """Publish to miner-events topic with acknowledgment monitoring."""
        return await self.publish_with_fallback(
            TOPICS.MINER_EVENTS,
            message,
            fallback_callback,
            acknowledgment_timeout,
            async_result
        )

    async def publish_to_system_events(
        self,
        message: PubSubMessage,
        fallback_callback: Callable | None = None,
        acknowledgment_timeout: float | None = None,
        async_result: bool | None = False
    ) -> dict:
        """Publish to system-events topic with acknowledgment monitoring."""
        return await self.publish_with_fallback(
            TOPICS.SYSTEM_EVENTS,
            message,
            fallback_callback,
            acknowledgment_timeout,
            async_result
        )

    async def publish_to_validation_events(
        self,
        message: PubSubMessage,
        fallback_callback: Callable | None = None,
        acknowledgment_timeout: float | None = None,
        async_result: bool | None = False
    ) -> dict:
        """Publish to validation-events topic with acknowledgment monitoring."""
        return await self.publish_with_fallback(
            TOPICS.VALIDATION_EVENTS,
            message,
            fallback_callback,
            acknowledgment_timeout,
            async_result
        )

    def set_message_callback(self, topic_name: str, callback: Callable):
        """
        Set the callback function for processing received messages.

        Args:
            callback: Function to call when messages are received
        """
        self._message_callbacks[topic_name] = callback

    def _default_message_callback(self, message):
        """Default message callback that logs and acknowledges messages."""
        try:
            # Decode the message data
            data = json.loads(message.data.decode("utf-8"))

            self.logger.info(f"Received Pub/Sub message: {data}")

            # Acknowledge the message
            message.ack()

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in message: {e}")
            message.nack()
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            message.nack()

    async def subscribe_to_topics(self):
        """
        Subscribe to all the pub sub topics.
        """
        if self.disabled:
            return

        # Ensure clients are initialized
        if not self._ensure_clients_initialized():
            return
        for topic_name in self.queues:
            await self.subscribe_to_messages_topic(topic_name=topic_name)

    async def subscribe_to_messages_topic(
        self,
        topic_name: str,
        subscription_name_suffix: str | None = None,
    ):
        """
        Subscribe to the pub sub topic.

        Args:
            subscription_name_suffix: Optional suffix for subscription name
        """
        if not self.subscriber:
            raise ConfigurationError("Subscriber client not initialized")

        try:
            project_id = self.auth.get_project_id()

            # Create unique subscription name
            if subscription_name_suffix:
                subscription_name = f"messages-sub-{topic_name}-{subscription_name_suffix}"
            else:
                subscription_name = f"messages-sub-{topic_name}-{self.wallet.hotkey.ss58_address[:8]}"

            subscription_path = self.subscriber.subscription_path(project_id, subscription_name)
            topic_path = self.subscriber.topic_path(project_id, topic_name)

            # Check if subscription exists, create if it doesn't
            try:
                self.subscriber.get_subscription(request={"subscription": subscription_path})
            except gcp_exceptions.NotFound:
                self.subscriber.create_subscription(
                    request={"name": subscription_path, "topic": topic_path}
                )

            # Use provided callback or default
            callback = self._message_callbacks.get(topic_name) or self._default_message_callback

            # Start subscription
            flow_control = pubsub_v1.types.FlowControl(max_messages=100)
            self.subscription_futures[topic_name] = self.subscriber.subscribe(
                subscription_path,
                callback=callback,
                flow_control=flow_control
            )

            self.logger.info(
                f"Successfully subscribed to messages topic {topic_name} on {self.config.subtensor.network} network"
            )

        except Exception as e:
            self.logger.error(f"Failed to subscribe to messages topic: {e}")
            raise ConfigurationError(f"Failed to subscribe to messages topic: {e}") from e

    def stop_subscription(self):
        """Stop the current subscription."""
        for topic_name in list(self.subscription_futures.keys()):
            try:
                if subscription_future := self.subscription_futures.pop(topic_name, None):
                    subscription_future.cancel()
                    subscription_future = None
                    self.logger.info("Pub/Sub subscription stopped")
            except Exception as e:
                self.logger.error(f"Error stopping subscription: {e}")

    def get_queue_status(self) -> dict:
        """Get current queue sizes."""
        return {topic: queue.qsize() for topic, queue in self.queues.items()}

    async def stop_queue_workers(self):
        """Stop all background queue workers."""
        self._worker_shutdown.set()

        if self._queue_workers:
            await asyncio.gather(*self._queue_workers.values(), return_exceptions=True)
            self._queue_workers.clear()

            # Log any remaining messages
            queue_status = self.get_queue_status()
            remaining = sum(queue_status.values())
            if remaining > 0:
                self.logger.warning(f"Stopping with {remaining} unpublished messages: {queue_status}")
            else:
                self.logger.info("All queue workers stopped, no pending messages")

    def close(self):
        """Close the client and stop subscriptions."""
        self.stop_subscription()

        # Signal workers to stop
        self._worker_shutdown.set()

        # Log any remaining messages
        if self._queue_workers:
            queue_status = self.get_queue_status()
            remaining = sum(queue_status.values())
            if remaining > 0:
                self.logger.warning(f"Closing with {remaining} unpublished messages: {queue_status}")

        if self.subscriber:
            self.subscriber.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        """Context manager exit."""
        self.close()
