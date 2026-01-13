import json
import os
import platform
import socket
import subprocess
import time
from typing import Optional, Tuple

import psutil

from .logging import log

_HW_STATIC_CACHE = None
_PYNVML_AVAILABLE = None


def _get_gpu_info():
    """
    Returns (gpus_static, gpus_live) using NVML when available, otherwise nvidia-smi.
    gpus_static: [{"name", "uuid", "mem_total_bytes"}, ...]
    gpus_live:   [{
        "utilization_gpu", "mem_total", "mem_used",
        "temperature", "power_watts",
        "pcie": {"tx_kb_s", "rx_kb_s"}
    }, ...]
    """
    global _PYNVML_AVAILABLE
    gpus_static = []
    gpus_live = []

    # Try NVML first (fast, in-process)
    if _PYNVML_AVAILABLE is None:
        try:
            import pynvml  # type: ignore

            pynvml.nvmlInit()
            _PYNVML_AVAILABLE = True
        except Exception:
            _PYNVML_AVAILABLE = False

    if _PYNVML_AVAILABLE:
        try:
            import pynvml  # type: ignore

            count = pynvml.nvmlDeviceGetCount()
            for i in range(count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                try:
                    name = pynvml.nvmlDeviceGetName(h)
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="ignore")
                except Exception:
                    name = "GPU"
                try:
                    uuid = pynvml.nvmlDeviceGetUUID(h)
                    if isinstance(uuid, bytes):
                        uuid = uuid.decode("utf-8", errors="ignore")
                except Exception:
                    uuid = None
                try:
                    mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                    mem_total = float(mem.total)
                    mem_used = float(mem.used)
                except Exception:
                    mem_total = 0.0
                    mem_used = 0.0
                try:
                    util = pynvml.nvmlDeviceGetUtilizationRates(h)
                    util_gpu = float(util.gpu)
                except Exception:
                    util_gpu = 0.0
                try:
                    temp = float(pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU))
                except Exception:
                    temp = 0.0
                try:
                    power_mw = float(pynvml.nvmlDeviceGetPowerUsage(h))
                    power_w = power_mw / 1000.0
                except Exception:
                    power_w = 0.0
                try:
                    tx_kb_s = float(pynvml.nvmlDeviceGetPcieThroughput(h, pynvml.NVML_PCIE_UTIL_TX_BYTES))
                except Exception:
                    tx_kb_s = 0.0
                try:
                    rx_kb_s = float(pynvml.nvmlDeviceGetPcieThroughput(h, pynvml.NVML_PCIE_UTIL_RX_BYTES))
                except Exception:
                    rx_kb_s = 0.0

                gpus_static.append(
                    {
                        "name": name,
                        "uuid": uuid,
                        "mem_total_bytes": int(mem_total) if mem_total else None,
                    }
                )
                gpus_live.append(
                    {
                        "utilization_gpu": util_gpu,
                        "mem_total": mem_total,
                        "mem_used": mem_used,
                        "temperature": temp,
                        "power_watts": power_w or None,
                        "pcie": {
                            "tx_kb_s": tx_kb_s,
                            "rx_kb_s": rx_kb_s,
                        },
                    }
                )
            return gpus_static, gpus_live
        except Exception as e:
            log("nvml_query_failed", level="warn", err=str(e))

    # Fallback: nvidia-smi CLI
    try:
        cmd = [
            "nvidia-smi",
            "--query-gpu=uuid,name,memory.total,utilization.gpu,memory.used,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=1.0)
        lines = out.decode().strip().splitlines()
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 7:
                continue
            uuid, name, mem_total_mb, util_gpu, mem_used_mb, temp_c, power_w = parts[:7]
            try:
                mem_total = float(mem_total_mb) * 1024 * 1024
            except Exception:
                mem_total = 0.0
            try:
                mem_used = float(mem_used_mb) * 1024 * 1024
            except Exception:
                mem_used = 0.0
            try:
                util_gpu_f = float(util_gpu)
            except Exception:
                util_gpu_f = 0.0
            try:
                temp_f = float(temp_c)
            except Exception:
                temp_f = 0.0
            try:
                power_f = float(power_w)
            except Exception:
                power_f = 0.0

            gpus_static.append(
                {
                    "name": name,
                    "uuid": uuid,
                    "mem_total_bytes": int(mem_total) if mem_total else None,
                }
            )
            gpus_live.append(
                {
                    "utilization_gpu": util_gpu_f,
                    "mem_total": mem_total,
                    "mem_used": mem_used,
                    "temperature": temp_f,
                    "power_watts": power_f or None,
                    "pcie": {
                        "tx_kb_s": 0.0,
                        "rx_kb_s": 0.0,
                    },
                }
            )
    except Exception as e:
        if "No such file or directory" not in str(e):
            log("nvidia_smi_failed", level="warn", err=str(e))

    return gpus_static, gpus_live


def _parse_cpuset_cpus(val: str) -> Optional[int]:
    """
    Parse a cpuset string like '0-3,5,7-8' into a count of CPUs.
    """
    if not val:
        return None
    count = 0
    for part in val.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                start = int(a)
                end = int(b)
                if end >= start:
                    count += end - start + 1
            except Exception:
                continue
        else:
            try:
                _ = int(part)
                count += 1
            except Exception:
                continue
    return count if count > 0 else None


def _get_cpuset_cores(host_logical: int) -> Optional[int]:
    """
    Returns the number of CPUs allowed by cpuset cgroup, if any.
    """
    paths = [
        "/sys/fs/cgroup/cpuset.cpus.effective",
        "/sys/fs/cgroup/cpuset.cpus",
        "/sys/fs/cgroup/cpuset/cpuset.cpus",
    ]
    for path in paths:
        try:
            if not os.path.exists(path):
                continue
            with open(path, "r") as f:
                val = f.read().strip()
            n = _parse_cpuset_cpus(val)
            if n is not None and n > 0:
                return min(n, host_logical)
        except Exception:
            continue
    return None


def _get_cpu_quota_cores(host_logical: int) -> Optional[float]:
    """
    Returns the number of CPUs allowed by CPU quota, if limited.
    """
    # cgroup v2: /sys/fs/cgroup/cpu.max
    try:
        path = "/sys/fs/cgroup/cpu.max"
        if os.path.exists(path):
            with open(path, "r") as f:
                line = f.read().strip()
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    quota_str, period_str = parts[0], parts[1]
                    if quota_str != "max":
                        quota = float(quota_str)
                        period = float(period_str)
                        if quota > 0.0 and period > 0.0:
                            cores = quota / period
                            if cores > 0.0:
                                return min(cores, float(host_logical))
    except Exception:
        pass

    # cgroup v1: /sys/fs/cgroup/cpu/cpu.cfs_quota_us, cpu.cfs_period_us
    try:
        q_path = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
        p_path = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
        if os.path.exists(q_path) and os.path.exists(p_path):
            with open(q_path, "r") as f:
                q = int(f.read().strip())
            with open(p_path, "r") as f:
                p = int(f.read().strip())
            if q > 0 and p > 0:
                cores = float(q) / float(p)
                if cores > 0.0:
                    return min(cores, float(host_logical))
    except Exception:
        pass

    return None


def _get_effective_cpu_counts() -> Tuple[int, int]:
    """
    Returns (logical_cores, physical_cores) accounting for cgroup limits if present.
    """
    host_logical = psutil.cpu_count(logical=True) or 1
    host_physical = psutil.cpu_count(logical=False) or host_logical

    cpuset_cores = _get_cpuset_cores(host_logical)
    quota_cores_f = _get_cpu_quota_cores(host_logical)

    candidates = [host_logical]
    if cpuset_cores is not None:
        candidates.append(cpuset_cores)
    if quota_cores_f is not None:
        qc = int(quota_cores_f + 0.5)
        if qc < 1:
            qc = 1
        candidates.append(qc)

    eff_logical = min(candidates) if candidates else host_logical
    if eff_logical < 1:
        eff_logical = 1

    eff_physical = min(eff_logical, host_physical) if host_physical else eff_logical
    if eff_physical < 1:
        eff_physical = 1

    return eff_logical, eff_physical


def _get_cgroup_memory_limit_and_usage(host_total: int) -> Tuple[Optional[int], Optional[int]]:
    """
    Returns (limit_bytes, usage_bytes) from cgroup if present and meaningful.
    limit_bytes will be None if unlimited or bogus.
    """
    limit = None
    usage = None

    # cgroup v2
    try:
        path_limit = "/sys/fs/cgroup/memory.max"
        path_usage = "/sys/fs/cgroup/memory.current"
        if os.path.exists(path_limit):
            with open(path_limit, "r") as f:
                val = f.read().strip()
            if val and val != "max":
                limit = int(val)
        if os.path.exists(path_usage):
            with open(path_usage, "r") as f:
                uval = f.read().strip()
            if uval:
                usage = int(uval)
    except Exception:
        pass

    # cgroup v1
    try:
        if limit is None:
            path_limit_v1 = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
            if os.path.exists(path_limit_v1):
                with open(path_limit_v1, "r") as f:
                    v = f.read().strip()
                if v:
                    limit = int(v)
        if usage is None:
            path_usage_v1 = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
            if os.path.exists(path_usage_v1):
                with open(path_usage_v1, "r") as f:
                    v = f.read().strip()
                if v:
                    usage = int(v)
    except Exception:
        pass

    # Filter unlimited / bogus limits
    if limit is not None:
        if limit <= 0:
            limit = None
        elif host_total and limit >= int(host_total * 0.99):
            limit = None
        elif limit >= (1 << 60):  # extremely large, treat as unlimited
            limit = None

    return limit, usage


def collect_hw_payload():
    """
    Collects hardware static inventory and live telemetry.

    Returns:
        (hw_static, hw_live) where each is a dict matching the heartbeat schema,
        or (None, None) on failure.
    """
    global _HW_STATIC_CACHE

    hw_static = _HW_STATIC_CACHE
    hw_live = None

    # GPU info (static + live)
    gpus_static = []
    gpus_live = []
    try:
        gpus_static, gpus_live = _get_gpu_info()
    except Exception as e:
        log("gpu_info_collection_failed", level="warn", err=str(e))

    # Static hardware (cached)
    if hw_static is None:
        try:
            hostname = None
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = None

            cpu_arch = platform.machine()
            cpu_model = platform.processor() or ""
            if not cpu_model:
                try:
                    if os.path.exists("/proc/cpuinfo"):
                        with open("/proc/cpuinfo", "r") as f:
                            for line in f:
                                if "model name" in line:
                                    cpu_model = line.split(":", 1)[1].strip()
                                    break
                except Exception:
                    pass

            vm = psutil.virtual_memory()
            host_total = vm.total

            cores_logical_eff, cores_physical_eff = _get_effective_cpu_counts()

            try:
                freq = psutil.cpu_freq()
            except Exception:
                freq = None

            freq_min = freq.min if freq and getattr(freq, "min", None) is not None else None
            freq_max = freq.max if freq and getattr(freq, "max", None) is not None else None

            # Determine RAM total (prefer cgroup limit if present)
            limit_bytes, _ = _get_cgroup_memory_limit_and_usage(host_total)
            if limit_bytes is not None:
                ram_total_bytes = int(limit_bytes)
            else:
                ram_total_bytes = int(host_total)

            # Static disks: capacity from "/", physical type/model from first physical disk
            disks_static = []
            disk_type = None
            model = None
            size_bytes = 0.0

            # Capacity: what the instance actually has on its root filesystem
            try:
                usage = psutil.disk_usage("/")
                size_bytes = float(usage.total)
            except Exception:
                size_bytes = 0.0

            # Physical disk info from lsblk (host-level)
            try:
                out = subprocess.check_output(
                    ["lsblk", "-bJo", "NAME,TYPE,SIZE,MODEL,TRAN,ROTA"],
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                )
                data = json.loads(out.decode() or "{}")
                devs = data.get("blockdevices") or []
                for d in devs:
                    if d.get("type") != "disk":
                        continue
                    tran = d.get("tran")
                    rota = d.get("rota")
                    model = d.get("model")
                    t = str(tran).lower() if tran is not None else None
                    r = None
                    if rota is not None:
                        try:
                            r = int(rota)
                        except Exception:
                            r = None
                    if t == "nvme":
                        disk_type = "nvme"
                    else:
                        if r == 0:
                            disk_type = "ssd"
                        elif r == 1:
                            disk_type = "hdd"
                    if disk_type is None and t:
                        disk_type = t
                    break
            except Exception:
                pass

            disks_static.append(
                {
                    "name": "/",
                    "type": disk_type,
                    "size_bytes": size_bytes,
                    "model": model,
                }
            )

            hw_static = {
                "system": {
                    "instance_id": hostname,
                    "instance_type": cpu_arch,
                    "region": None,
                },
                "cpu": {
                    "model": cpu_model or None,
                    "arch": cpu_arch,
                    "cores_logical": cores_logical_eff,
                    "cores_physical": cores_physical_eff,
                    "freq_min_mhz": freq_min,
                    "freq_max_mhz": freq_max,
                },
                "ram": {
                    "total_bytes": ram_total_bytes,
                },
                "disks": disks_static,
                "gpus": gpus_static,
            }
            _HW_STATIC_CACHE = hw_static
        except Exception as e:
            log("static_hw_collection_failed", level="warn", err=str(e))
            hw_static = None

    # Live telemetry (fast path)
    try:
        cpu_pct = psutil.cpu_percent(interval=None)
        try:
            load1, load5, load15 = os.getloadavg()
        except (AttributeError, OSError):
            load1 = load5 = load15 = None
        try:
            freq = psutil.cpu_freq()
        except Exception:
            freq = None
        freq_cur = freq.current if freq and getattr(freq, "current", None) is not None else None

        temp_c = None
        try:
            temps = psutil.sensors_temperatures()
            if isinstance(temps, dict):
                for k, arr in temps.items():
                    if arr:
                        t0 = arr[0]
                        val = getattr(t0, "current", None)
                        if val is not None:
                            temp_c = float(val)
                            break
        except Exception:
            temp_c = None

        vm = psutil.virtual_memory()
        host_total_live = vm.total
        limit_bytes_live, usage_bytes_live = _get_cgroup_memory_limit_and_usage(host_total_live)

        if limit_bytes_live is not None:
            total_live = float(limit_bytes_live)
            used_live = float(usage_bytes_live) if usage_bytes_live is not None else float(vm.used)
            if used_live > total_live:
                used_live = total_live
            avail_live = max(0.0, total_live - used_live)
            percent_live = (used_live / total_live * 100.0) if total_live > 0.0 else 0.0
        else:
            total_live = float(vm.total)
            used_live = float(vm.used)
            avail_live = float(vm.available)
            percent_live = float(vm.percent)

        sm = psutil.swap_memory()
        uptime_sec = None
        try:
            uptime_sec = float(time.time() - psutil.boot_time())
        except Exception:
            uptime_sec = None
        try:
            process_count = len(psutil.pids())
        except Exception:
            process_count = None

        hw_live = {
            "cpu": {
                "utilization_total": float(cpu_pct),
                "load_1": float(load1) if load1 is not None else None,
                "load_5": float(load5) if load5 is not None else None,
                "load_15": float(load15) if load15 is not None else None,
                "freq_current_mhz": freq_cur,
                "temp_c": temp_c,
            },
            "ram": {
                "used": int(used_live),
                "available": int(avail_live),
                "percent": float(percent_live),
            },
            "swap": {
                "used": int(sm.used),
                "percent": float(sm.percent),
            },
            "gpus": gpus_live,
            "disk": {
                "io_by_disk": [],
            },
            "net": {
                "by_iface": [],
            },
            "system": {
                "uptime_sec": uptime_sec,
                "process_count": process_count,
            },
        }
    except Exception as e:
        log("live_hw_collection_failed", level="warn", err=str(e))
        hw_live = None

    return hw_static, hw_live
