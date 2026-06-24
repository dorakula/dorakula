"""Performance Monitor - System stats and command timing using psutil."""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional


logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available - system monitoring will be limited")


@dataclass
class TimingRecord:
    """Record of a timed operation."""
    name: str
    start_time: float
    end_time: float
    duration: float
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class PerformanceMonitor:
    """Monitors system performance and tracks operation timing."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.timing_records: List[TimingRecord] = []
        self.baseline_stats: Optional[Dict[str, Any]] = None
        self.alert_thresholds: Dict[str, float] = {
            "cpu_percent": 90.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0,
            "open_files": 900.0,
        }

    def get_system_stats(self) -> Dict[str, Any]:
        """Get current system performance statistics."""
        if not HAS_PSUTIL:
            return self._get_basic_stats()

        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net_io = psutil.net_io_counters()
            process_count = len(psutil.pids())

            stats = {
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "load_avg": self._get_load_avg(),
                },
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "percent": memory.percent,
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "used_gb": round(disk.used / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "percent": disk.percent,
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errin": net_io.errin,
                    "errout": net_io.errout,
                },
                "process_count": process_count,
                "timestamp": time.time(),
            }

            if self.baseline_stats is None:
                self.baseline_stats = stats

            self._check_alerts(stats)
            return stats

        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return self._get_basic_stats()

    def _get_basic_stats(self) -> Dict[str, Any]:
        """Get basic stats without psutil."""
        try:
            with open("/proc/loadavg") as f:
                load = f.read().split()[:3]
            with open("/proc/meminfo") as f:
                mem_lines = f.readlines()
            mem_total = int(mem_lines[0].split()[1]) * 1024
            mem_available = int(mem_lines[2].split()[1]) * 1024
            return {
                "cpu": {"load_avg": load},
                "memory": {
                    "total_gb": round(mem_total / (1024**3), 2),
                    "available_gb": round(mem_available / (1024**3), 2),
                    "percent": round((1 - mem_available / mem_total) * 100, 1),
                },
                "timestamp": time.time(),
                "limited": True,
            }
        except Exception as e:
            logger.debug("Failed to read basic system stats: %s", e)
            return {"error": "Could not read system stats", "timestamp": time.time()}

    def _get_load_avg(self) -> List[float]:
        """Get system load average."""
        try:
            if HAS_PSUTIL:
                return list(psutil.getloadavg())
            with open("/proc/loadavg") as f:
                return [float(x) for x in f.read().split()[:3]]
        except Exception as e:
            logger.debug("Failed to get load average: %s", e)
            return [0.0, 0.0, 0.0]

    def _check_alerts(self, stats: Dict[str, Any]) -> None:
        """Check if any metrics exceed alert thresholds."""
        cpu_pct = stats.get("cpu", {}).get("percent", 0)
        mem_pct = stats.get("memory", {}).get("percent", 0)
        disk_pct = stats.get("disk", {}).get("percent", 0)

        if cpu_pct > self.alert_thresholds["cpu_percent"]:
            logger.warning(f"High CPU usage: {cpu_pct}%")
        if mem_pct > self.alert_thresholds["memory_percent"]:
            logger.warning(f"High memory usage: {mem_pct}%")
        if disk_pct > self.alert_thresholds["disk_percent"]:
            logger.warning(f"High disk usage: {disk_pct}%")

    @asynccontextmanager
    async def time_operation(
        self, name: str, metadata: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[None]:
        """Context manager to time an async operation."""
        start = time.time()
        success = True
        try:
            yield
        except Exception as e:
            success = False
            logger.debug("Operation '%s' failed: %s", name, e)
            raise
        finally:
            end = time.time()
            duration = end - start
            record = TimingRecord(
                name=name,
                start_time=start,
                end_time=end,
                duration=duration,
                success=success,
                metadata=metadata or {},
            )
            self.timing_records.append(record)
            status = "completed" if success else "failed"
            logger.info(f"Operation '{name}' {status} in {duration:.3f}s")

    def get_timing_summary(self) -> Dict[str, Any]:
        """Get a summary of all timed operations."""
        if not self.timing_records:
            return {"total_operations": 0}

        by_name: Dict[str, List[TimingRecord]] = {}
        for record in self.timing_records:
            by_name.setdefault(record.name, []).append(record)

        summary: Dict[str, Any] = {}
        for name, records in by_name.items():
            durations = [r.duration for r in records]
            success_count = sum(1 for r in records if r.success)
            summary[name] = {
                "count": len(records),
                "success_count": success_count,
                "failure_count": len(records) - success_count,
                "total_time": round(sum(durations), 3),
                "avg_time": round(sum(durations) / len(durations), 3),
                "min_time": round(min(durations), 3),
                "max_time": round(max(durations), 3),
            }

        all_durations = [r.duration for r in self.timing_records]
        return {
            "total_operations": len(self.timing_records),
            "overall_avg": round(sum(all_durations) / len(all_durations), 3),
            "by_operation": summary,
        }

    async def get_performance_report(self) -> Dict[str, Any]:
        """Generate a comprehensive performance report."""
        stats = self.get_system_stats()
        timing = self.get_timing_summary()

        return {
            "system": stats,
            "timing": timing,
            "baseline_comparison": self._compare_to_baseline(stats),
        }

    def _compare_to_baseline(self, current: Dict[str, Any]) -> Dict[str, Any]:
        """Compare current stats to baseline."""
        if not self.baseline_stats:
            return {"status": "no_baseline"}

        comparison: Dict[str, Any] = {}
        current_mem_pct = current.get("memory", {}).get("percent", 0)
        baseline_mem_pct = self.baseline_stats.get("memory", {}).get("percent", 0)
        mem_delta = current_mem_pct - baseline_mem_pct

        current_cpu_pct = current.get("cpu", {}).get("percent", 0)
        baseline_cpu_pct = self.baseline_stats.get("cpu", {}).get("percent", 0)
        cpu_delta = current_cpu_pct - baseline_cpu_pct

        comparison["memory_delta"] = round(mem_delta, 1)
        comparison["cpu_delta"] = round(cpu_delta, 1)

        if mem_delta > 20:
            comparison["memory_status"] = "significant_increase"
        elif mem_delta > 10:
            comparison["memory_status"] = "moderate_increase"
        else:
            comparison["memory_status"] = "stable"

        if cpu_delta > 30:
            comparison["cpu_status"] = "significant_increase"
        elif cpu_delta > 15:
            comparison["cpu_status"] = "moderate_increase"
        else:
            comparison["cpu_status"] = "stable"

        return comparison
