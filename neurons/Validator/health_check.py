#!/usr/bin/env python3
"""
Health Check Module

This module handles healthcheck independently from POG (Proof of Generation).
It runs after POG has finished to verify miner connectivity.
"""

import paramiko
import time
import bittensor as bt
import requests


class EphemeralContainerHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Custom host key policy for ephemeral container connections.

    Accepts and stores host keys without verification for containers that are
    freshly created and have no pre-established trust relationship. This is
    appropriate for ephemeral containers where the host key changes on each
    container creation.
    """
    def missing_host_key(self, client, hostname, key):
        # Accept and store host key for ephemeral container connection
        client._host_keys.add(hostname, key.get_name(), key)


def upload_health_check_script(ssh_client: paramiko.SSHClient, health_check_script_path: str) -> bool:
    """
    Uploads the health check script to the miner using SFTP.

    Args:
        ssh_client (paramiko.SSHClient): SSH client connected to the miner
        health_check_script_path (str): Local path of the health check script

    Returns:
        bool: True if uploaded successfully, False otherwise
    """
    try:
        sftp = ssh_client.open_sftp()
        sftp.put(health_check_script_path, "/tmp/health_check_server.py")
        sftp.chmod("/tmp/health_check_server.py", 0o755)
        sftp.close()
        return True
    except Exception as e:
        bt.logging.debug(f"Failed to upload health check script - SFTP error: {e}")
        return False

def start_health_check_server_background(ssh_client: paramiko.SSHClient, port: int = 27015, timeout: int = 60) -> tuple[bool, paramiko.Channel | None]:
    """
    Starts the health check server using Paramiko channels.

    Args:
        ssh_client (paramiko.SSHClient): SSH client connected to the miner
        port (int): Port for the health check server
        timeout (int): Wait time in seconds (default 60 seconds)

    Returns:
        tuple: (bool, channel) - (True if started successfully, channel object)
    """
    channel = None
    try:
        # Use paramiko transport and channel
        transport = ssh_client.get_transport()
        channel = transport.open_session()

        # Execute the health check server command using channel
        command = f"python3 /tmp/health_check_server.py --port {port} --timeout {timeout}"
        bt.logging.trace(f"Executing remote command: {command}")
        channel.exec_command(command)

        # Check if the channel is still active (server is running)
        if not channel.closed:
            bt.logging.trace("Remote server channel is open.")
            return True, channel
        else:
            # If the channel closed immediately, it means the command failed to start the server.
            # Collect *all* output for debugging this immediate failure.
            stdout_output = ""
            stderr_output = ""
            while channel.recv_ready():
                stdout_output += channel.recv(4096).decode('utf-8', errors='ignore')
            while channel.recv_stderr_ready():
                stderr_output += channel.recv_stderr(4096).decode('utf-8', errors='ignore')

            bt.logging.debug(f"Health check server crashed immediately on startup - check server logs below")
            if stdout_output:
                bt.logging.debug(f"Server stdout: {stdout_output.strip()}")
            if stderr_output:
                bt.logging.debug(f"Server stderr: {stderr_output.strip()}")

            if channel:
                channel.close()
            return False, None

    except Exception as e:
        bt.logging.debug(f"Failed to start health check server - transport error: {e}")
        if channel:
            channel.close()
        return False, None

def read_channel_output(channel: paramiko.Channel, hk: str = "") -> None:
    """
    Reads and logs *all available* output from the channel's stdout and stderr streams
    without blocking indefinitely. This function is designed to drain the buffers.

    Args:
        channel: Paramiko channel object
        hk (str): Shortened hotkey for logging context
    """
    current_stdout = ""
    current_stderr = ""

    try:
        # Read all available stdout
        while channel.recv_ready():
            current_stdout += channel.recv(4096).decode('utf-8', errors='ignore')

        # Read all available stderr
        while channel.recv_stderr_ready():
            current_stderr += channel.recv_stderr(4096).decode('utf-8', errors='ignore')

        # Log any output found in this cycle
        if current_stdout:
            bt.logging.trace(f"[{hk}] server stdout: {current_stdout.strip()}")
        if current_stderr:
            bt.logging.trace(f"[{hk}] server stderr: {current_stderr.strip()}")

    except Exception as e:
        bt.logging.trace(f"[{hk}] error reading channel: {e}")


def wait_for_port_ready(ssh_client: paramiko.SSHClient, port: int = 27015, timeout: int = 30, hk: str = "") -> bool:
    """
    Waits for a health endpoint to become available using urllib.request.

    This function checks if the health check server is responding by making
    HTTP requests to the root endpoint (/) on the specified port.

    Args:
        ssh_client (paramiko.SSHClient): SSH client connected to the miner
        port (int): Port to check
        timeout (int): Maximum time to wait in seconds
        hk (str): Shortened hotkey for logging context

    Returns:
        bool: True if health endpoint becomes available within timeout, False otherwise
    """
    start_time = time.time()
    check_interval = 1

    while time.time() - start_time < timeout:
        try:
            command = f'python3 -c \'import urllib.request; urllib.request.urlopen("http://127.0.0.1:{port}/", timeout=2)\''

            stdin, stdout, stderr = ssh_client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                bt.logging.trace(f"[{hk}] port {port} responding")
                return True

        except Exception as e:
            bt.logging.trace(f"[{hk}] port check error: {e}")

        time.sleep(check_interval)

    bt.logging.trace(f"[{hk}] port {port} not responding after {timeout}s")
    return False

def kill_health_check_server(ssh_client: paramiko.SSHClient, port: int = 27015) -> bool:
    """
    Kills the health check server process using PID file.

    Args:
        ssh_client (paramiko.SSHClient): SSH client connected to the miner
        port (int): Port of the health check server

    Returns:
        bool: True if killed successfully, False otherwise
    """
    try:
        pid_file_path = f"/tmp/health_check_server_{port}.pid"

        # Read PID from file
        stdin, stdout, stderr = ssh_client.exec_command(f"cat {pid_file_path} 2>/dev/null || echo ''")
        pid_output = stdout.read().decode('utf-8').strip()

        if not pid_output:
            bt.logging.trace(f"Health check server PID file not found, server may not be running")
            return True

        try:
            pid = int(pid_output)
        except ValueError:
            bt.logging.trace(f"Invalid PID in file: {pid_output}")
            return True

        # Kill process using PID
        stdin, stdout, stderr = ssh_client.exec_command(f"kill {pid} 2>/dev/null || echo 'Process not found'")
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            bt.logging.trace(f"Health check server (PID: {pid}) killed successfully")
            return True
        else:
            bt.logging.trace(f"Health check server (PID: {pid}) was not running or already killed")
            return True

    except Exception as e:
        bt.logging.trace(f"Error killing health check server: {e}")
        return False

def wait_for_health_check(host: str, port: int, timeout: int = 30, retry_interval: int = 1) -> bool:
    """
    Waits for the health check server to be available via HTTP.

    Args:
        host (str): Miner host
        port (int): Health check server port
        timeout (int): Maximum wait time in seconds
        retry_interval (int): Interval between retries in seconds

    Returns:
        bool: True if health check is successful, False otherwise
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"http://{host}:{port}", timeout=2)

            if response.status_code == 200:
                bt.logging.trace(f"HTTP Health check successful on {host}:{port}!")
                return True
            else:
                bt.logging.debug(f"HTTP Health check server returned status code {response.status_code} instead of 200 on {host}:{port}")
                # Continue to next iteration - don't return here

        except requests.exceptions.ConnectionError as e:
            bt.logging.trace(f"HTTP Connection error to {host}:{port}: {e}")
        except requests.exceptions.Timeout as e:
            bt.logging.trace(f"HTTP Timeout error to {host}:{port}: {e}")
        except requests.exceptions.RequestException as e:
            bt.logging.trace(f"HTTP Request error to {host}:{port}: {e}")

        time.sleep(retry_interval)

    bt.logging.debug(f"External health check failed on {host}:{port} - port may be blocked by firewall or miner is misconfigured")
    return False

def perform_health_check(
    axon: bt.AxonInfo,
    miner_info: dict[str, str | int],
    ssh_private_key=None
) -> bool:
    """
    Performs health check on a miner after POG has finished.

    Args:
        axon: Axon information of the miner
        miner_info: Miner information (host, port, etc.) - always provided by POG
        ssh_private_key: The validator's SSH private key for authentication

    Returns:
        bool: True if health check is successful, False otherwise
    """
    hotkey = axon.hotkey
    hk = hotkey[:8]  # shortened for logging
    host: str | None = None
    ssh_client: paramiko.SSHClient | None = None
    channel: paramiko.Channel | None = None

    try:
        host = miner_info['host']

        # Connect via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(EphemeralContainerHostKeyPolicy())
        try:
            bt.logging.trace(f"[{hk}] attempting SSH connection to {host}")
            ssh_client.connect(host, port=miner_info.get('port', 22), username=miner_info['username'], pkey=ssh_private_key, timeout=10)
            bt.logging.trace(f"[{hk}] SSH connection successful")
        except Exception as ssh_error:
            bt.logging.debug(f"[{hk}] SSH connection failed: {ssh_error}")
            return False

        health_check_script_path = "neurons/Validator/health_check_server.py"

        if not upload_health_check_script(ssh_client, health_check_script_path):
            bt.logging.debug(f"[{hk}] failed to upload health check script")
            return False

        # Get external ports to validate
        external_user_ports = miner_info.get('external_user_ports', {})

        # Start health check servers on all internal ports
        channels = []
        internal_ports = list(external_user_ports.keys())

        for internal_port in internal_ports:
            bt.logging.trace(f"[{hk}] starting health check server on port {internal_port}")
            server_started, channel = start_health_check_server_background(ssh_client, int(internal_port), timeout=60)

            if not server_started or channel is None:
                bt.logging.debug(f"[{hk}] failed to start health check server on port {internal_port}")
                # Close any previously opened channels
                for ch in channels:
                    if ch and not ch.closed:
                        ch.close()
                return False

            channels.append(channel)

        server_ready_timeout = 15

        # Wait for all servers to be ready
        for internal_port in internal_ports:
            bt.logging.trace(f"[{hk}] checking health server readiness on port {internal_port}")
            if not wait_for_port_ready(ssh_client, int(internal_port), server_ready_timeout, hk):
                bt.logging.debug(f"[{hk}] health check server on port {internal_port} not ready")
                # Close all channels
                for ch in channels:
                    if ch and not ch.closed:
                        ch.close()
                return False

        bt.logging.trace(f"[{hk}] all health check servers ready")

        health_check_timeout = 15
        health_check_retry_interval = 1

        # Validate all external ports
        all_ports_valid = True
        for internal_port, external_port in external_user_ports.items():
            bt.logging.trace(f"[{hk}] HTTP health check {host}:{external_port}")

            health_check_success = wait_for_health_check(
                host,
                external_port,
                timeout=health_check_timeout,
                retry_interval=health_check_retry_interval
            )

            if not health_check_success:
                bt.logging.debug(f"[{hk}] health check failed for port {external_port}")
                all_ports_valid = False
                break
            else:
                bt.logging.trace(f"[{hk}] port {external_port} OK")

        # Read output from all channels
        for channel in channels:
            if channel and not channel.closed:
                bt.logging.trace(f"[{hk}] reading server output")
                read_channel_output(channel, hk)

        if not all_ports_valid:
            # Close all channels before returning
            for channel in channels:
                if channel and not channel.closed:
                    channel.close()
            return False

        # Kill all health check servers
        bt.logging.trace(f"[{hk}] stopping health check servers")
        for internal_port in internal_ports:
            if kill_health_check_server(ssh_client, int(internal_port)):
                bt.logging.trace(f"[{hk}] server on port {internal_port} stopped")
            else:
                bt.logging.trace(f"[{hk}] server on port {internal_port} may self-terminate")

        # Read final output and close all channels
        for channel in channels:
            if channel and not channel.closed:
                bt.logging.trace(f"[{hk}] reading final output")
                read_channel_output(channel, hk)
                channel.close()

        return True

    except Exception as e:
        bt.logging.debug(f"[{hk}] health check error: {e}")
        return False

    finally:
        if ssh_client is not None:
            try:
                if channel and not channel.closed:
                    channel.close()
                ssh_client.close()
            except Exception:
                pass  # cleanup errors are not important
