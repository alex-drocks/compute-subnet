import os
import multiprocessing
from typing import Optional, Dict, Any


_PROC: Optional[multiprocessing.Process] = None


def _child_main(env_overrides: Optional[Dict[str, str]] = None) -> None:
    """
    Child process entry point.
    env_overrides are applied to os.environ BEFORE importing scheduler,
    ensuring config modules see the correct values.
    """
    # Apply env overrides in child process only (doesn't affect parent)
    if env_overrides:
        os.environ.update(env_overrides)

    from . import scheduler  # imported inside child to ensure env is applied first

    scheduler.main_loop()


def start_pog_loop(env_overrides: Optional[Dict[str, Any]] = None) -> None:
    """
    Spawn the PoG miner loop in a separate process.
    env_overrides: key/value pairs to inject into the child environment (strings).

    Note: env_overrides are passed to the child process and applied there,
    avoiding pollution of the parent process environment.
    """
    global _PROC
    if _PROC is not None and _PROC.is_alive():
        return

    # Convert env_overrides to string dict (required for os.environ)
    # Pass to child instead of modifying parent's os.environ
    child_env: Optional[Dict[str, str]] = None
    if env_overrides:
        child_env = {str(k): str(v) for k, v in env_overrides.items() if v is not None}

    # Import `scheduler` only inside the spawned process; otherwise config is evaluated
    # in the parent before `env_overrides` is applied, and the child inherits the stale config.
    _PROC = multiprocessing.Process(target=_child_main, args=(child_env,), daemon=True)
    _PROC.start()


def stop_pog_loop() -> None:
    global _PROC
    if _PROC is None:
        return
    try:
        if _PROC.is_alive():
            _PROC.terminate()
            _PROC.join(timeout=10)
            # If process didn't terminate within timeout, force kill
            if _PROC.is_alive():
                _PROC.kill()
                _PROC.join(timeout=5)
    finally:
        _PROC = None
