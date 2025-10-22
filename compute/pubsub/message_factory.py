"""
Message factory for creating type-safe pub/sub messages.

This module provides a convenient factory class for creating properly
formatted messages for validator-backend communication.
"""

from datetime import datetime, timezone

from .message_types import (
    GpuDeallocationPubSubMessage,
    GpuStatusChangePubSubMessage,
    MinerAllocationMessage,
    MinerDeallocationMessage,
    PogResultMessage,
    BenchmarkData,
)


class MessageFactory:
    """Factory class for creating pub/sub messages with proper formatting."""

    def __init__(self, source: str, validator_hotkey: str):
        """
        Initialize the message factory.

        Args:
            validator_hotkey: The hotkey of the validator creating messages
        """
        self.source = source
        self.validator_hotkey = validator_hotkey

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO 8601 format."""
        return datetime.now(tz=timezone.utc).isoformat() + "Z"

    def create_pog_result(
        self,
        miner_hotkey: str,
        request_id: str,
        result: str,
        validation_duration_seconds: float,
        benchmark_data: dict | None = None,
        error_details: str | None = None,
        health_check_result: bool | None = None,
    ) -> PogResultMessage:
        """
        Create a PoG result message.

        Args:
            miner_hotkey: The hotkey of the validated miner
            request_id: The request ID from the original PoG request
            result: Result of validation ("success", "failure", "timeout", "error")
            validation_duration_seconds: How long the validation took
            benchmark_data: Optional benchmark data dict
            error_details: Optional error details if result was error/failure

        Returns:
            PogResultMessage instance
        """
        benchmark_obj = None
        if benchmark_data:
            benchmark_obj = BenchmarkData(
                reported_gpu_number=benchmark_data["reported_gpu_number"],
                reported_gpu_name=benchmark_data["reported_gpu_name"],
                vram=benchmark_data["vram"],
                size_fp16=benchmark_data["size_fp16"],
                time_fp16=benchmark_data["time_fp16"],
                size_fp32=benchmark_data["size_fp32"],
                time_fp32=benchmark_data["time_fp32"],
                fp16_tflops=benchmark_data["fp16_tflops"],
                fp32_tflops=benchmark_data["fp32_tflops"],
                identified_gpu_number=benchmark_data["identified_gpu_number"],
                identified_gpu_name=benchmark_data["identified_gpu_name"],
                average_multiplication_time=benchmark_data["average_multiplication_time"],
                average_merkle_tree_time=benchmark_data["average_merkle_tree_time"],
                verification_passed=benchmark_data["verification_passed"],
                timing_passed=benchmark_data["timing_passed"],
            )

        return PogResultMessage(
            validator_hotkey=self.validator_hotkey,
            miner_hotkey=miner_hotkey,
            request_id=request_id,
            result=result,
            validation_duration_seconds=validation_duration_seconds,
            benchmark_data=benchmark_obj,
            error_details=error_details,
            message_type="",  # Will be set in __post_init__
            timestamp=self._get_timestamp(),
            source=self.source,
            health_check_result=health_check_result,
        )

    def create_miner_deallocation(
        self,
        miner_hotkey: str,
        retry_count: int | None = None,
        deallocation_result: bool | None = None,
        deallocation_error: str | None = None,
    ) -> MinerDeallocationMessage:
        """
        Create a Miner deallocation message.

        Args:
            miner_hotkey: The hotkey of the deallocated miner
            retry_count: Optional retry count
            deallocation_result: Optional deallocation result
            deallocation_error: Optional deallocation error

        Returns:
            MinerDeallocationMessage instance
        """
        return MinerDeallocationMessage(
            validator_hotkey=self.validator_hotkey,
            miner_hotkey=miner_hotkey,
            retry_count=retry_count,
            deallocation_result=deallocation_result,
            deallocation_error=deallocation_error,
            timestamp=self._get_timestamp(),
            source=self.source,
        )

    def create_miner_allocation(
        self,
        miner_hotkey: str,
        allocation_result: bool | None = None,
        allocation_error: str | None = None,
    ) -> MinerAllocationMessage:
        """
        Create a Miner allocation message.

        Args:
            miner_hotkey: The hotkey of the deallocated miner
            allocation_result: Optional allocation result
            allocation_error: Optional allocation error

        Returns:
            MinerAllocationMessage instance
        """
        return MinerAllocationMessage(
            validator_hotkey=self.validator_hotkey,
            miner_hotkey=miner_hotkey,
            allocation_result=allocation_result,
            allocation_error=allocation_error,
            timestamp=self._get_timestamp(),
            source=self.source,
        )

    def create_gpu_status_change(
        self,
        miner_hotkey: str,
        previous_status: str,
        current_status: str,
        allocation_uuid: str | None = None,
        reason: str | None = None,
        priority: str = "normal",
        correlation_id: str | None = None,
    ) -> GpuStatusChangePubSubMessage:
        """
        Create a GPU status change pub/sub message.

        Args:
            miner_hotkey: The hotkey of the miner
            previous_status: Previous status
            current_status: Current status
            allocation_uuid: Optional allocation UUID
            reason: Optional reason for status change
            priority: Message priority
            correlation_id: Optional correlation ID for tracking

        Returns:
            GpuStatusChangePubSubMessage instance
        """
        return GpuStatusChangePubSubMessage(
            message_type="",  # Will be set in __post_init__
            timestamp=self._get_timestamp(),
            source=self.source,
            priority=priority,
            correlation_id=correlation_id,
            validator_hotkey=self.validator_hotkey,
            miner_hotkey=miner_hotkey,
            previous_status=previous_status,
            current_status=current_status,
            allocation_uuid=allocation_uuid,
            reason=reason,
        )

    def create_gpu_deallocation(
        self,
        miner_hotkey: str,
        allocation_uuid: str,
        deallocation_reason: str,
        gpu_model: str | None = None,
        allocation_duration_minutes: int | None = None,
        user_id: str | None = None,
        allocation_start_time: str | None = None,
        priority: str = "high",
        correlation_id: str | None = None,
    ) -> GpuDeallocationPubSubMessage:
        """
        Create a GPU deallocation pub/sub message.

        Args:
            miner_hotkey: The hotkey of the miner
            allocation_uuid: Allocation UUID
            deallocation_reason: Reason for deallocation
            gpu_model: Optional GPU model name
            allocation_duration_minutes: Optional duration of allocation
            user_id: Optional user ID who had the allocation
            allocation_start_time: Optional allocation start time
            priority: Message priority
            correlation_id: Optional correlation ID for tracking

        Returns:
            GpuDeallocationPubSubMessage instance
        """
        return GpuDeallocationPubSubMessage(
            message_type="",  # Will be set in __post_init__
            timestamp=self._get_timestamp(),
            source=self.source,
            priority=priority,
            correlation_id=correlation_id,
            validator_hotkey=self.validator_hotkey,
            miner_hotkey=miner_hotkey,
            allocation_uuid=allocation_uuid,
            deallocation_reason=deallocation_reason,
            gpu_model=gpu_model,
            allocation_duration_minutes=allocation_duration_minutes,
            user_id=user_id,
            allocation_start_time=allocation_start_time,
        )


# Convenience functions for common status changes
def create_allocation_started_message(
    factory: MessageFactory,
    miner_hotkey: str,
    allocation_uuid: str,
    user_id: str | None = None,
    correlation_id: str | None = None,
) -> GpuStatusChangePubSubMessage:
    """Create a pub/sub message for when GPU allocation starts."""
    return factory.create_gpu_status_change(
        miner_hotkey=miner_hotkey,
        previous_status="online",
        current_status="allocated",
        allocation_uuid=allocation_uuid,
        reason=f"allocation_started_for_user_{user_id}" if user_id else "allocation_started",
        priority="high",
        correlation_id=correlation_id,
    )


def create_allocation_ended_message(
    factory: MessageFactory,
    miner_hotkey: str,
    allocation_uuid: str,
    reason: str = "allocation_completed",
    correlation_id: str | None = None,
) -> GpuStatusChangePubSubMessage:
    """Create a pub/sub message for when GPU allocation ends."""
    return factory.create_gpu_status_change(
        miner_hotkey=miner_hotkey,
        previous_status="allocated",
        current_status="online",
        allocation_uuid=allocation_uuid,
        reason=reason,
        priority="normal",
        correlation_id=correlation_id,
    )


def create_miner_offline_message(
    factory: MessageFactory,
    miner_hotkey: str,
    reason: str = "miner_disconnected",
    correlation_id: str | None = None,
    allocation_uuid: str | None = None,
) -> GpuStatusChangePubSubMessage:
    """Create a pub/sub message for when miner goes offline."""
    return factory.create_gpu_status_change(
        miner_hotkey=miner_hotkey,
        previous_status="online",
        current_status="offline",
        allocation_uuid=allocation_uuid,
        reason=reason,
        priority="high",
        correlation_id=correlation_id,
    )


def create_miner_online_message(
    factory: MessageFactory,
    miner_hotkey: str,
    reason: str = "miner_reconnected",
    correlation_id: str | None = None,
    allocation_uuid: str | None = None,
) -> GpuStatusChangePubSubMessage:
    """Create a pub/sub message for when miner comes online."""
    return factory.create_gpu_status_change(
        miner_hotkey=miner_hotkey,
        previous_status="offline",
        current_status="online",
        allocation_uuid=allocation_uuid,
        reason=reason,
        priority="normal",
        correlation_id=correlation_id,
    )
