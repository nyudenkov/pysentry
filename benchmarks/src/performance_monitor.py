import platform
import statistics
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

import psutil


@dataclass
class RunResult:
    """Metrics for a single execution of a tool."""

    execution_time: float  # seconds
    peak_memory_mb: float  # megabytes, summed over the process tree
    exit_code: int
    raw_vulns: int  # count the tool printed (-1 if unparseable)
    canonical_vulns: int  # distinct after collapsing advisory aliases (-1 if bad)
    stdout: str = ""
    stderr: str = ""


@dataclass
class AggregatedMetrics:
    """Summary of N runs of the same configuration. Scalars are medians."""

    execution_time: float  # median
    peak_memory_mb: float  # median
    time_min: float
    time_stdev: float
    mem_min: float
    mem_stdev: float
    raw_vulns: int  # what the tool reported
    canonical_vulns: int  # distinct after alias collapse
    exit_code: int
    runs: int


def aggregate(runs: list[RunResult]) -> AggregatedMetrics:
    # A single transient failure (network blip on a cold DB fetch) must not
    # corrupt the median or zero the vuln column. Aggregate over successful runs
    # only; take the best parsed vuln count. Fall back to all runs if none passed.
    ok = [r for r in runs if r.exit_code <= 1 and r.canonical_vulns >= 0] or runs
    times = [r.execution_time for r in ok]
    mems = [r.peak_memory_mb for r in ok]
    return AggregatedMetrics(
        execution_time=statistics.median(times),
        peak_memory_mb=statistics.median(mems),
        time_min=min(times),
        time_stdev=statistics.stdev(times) if len(times) > 1 else 0.0,
        mem_min=min(mems),
        mem_stdev=statistics.stdev(mems) if len(mems) > 1 else 0.0,
        raw_vulns=max(r.raw_vulns for r in runs),
        canonical_vulns=max(r.canonical_vulns for r in runs),
        exit_code=ok[-1].exit_code,
        runs=len(ok),
    )


@dataclass
class SystemInfo:
    platform: str
    python_version: str
    cpu_count: int
    total_memory_gb: float
    available_memory_gb: float

    @classmethod
    def get_current(cls) -> "SystemInfo":
        memory = psutil.virtual_memory()
        return cls(
            platform=platform.platform(),
            python_version=platform.python_version(),
            cpu_count=psutil.cpu_count(),
            total_memory_gb=memory.total / (1024**3),
            available_memory_gb=memory.available / (1024**3),
        )


class PerformanceMonitor:
    def __init__(self, sample_interval: float = 0.05):
        self.sample_interval = sample_interval
        self.reset()

    def reset(self):
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.peak_memory: float = 0.0
        self.monitoring = False
        self._monitor_thread: threading.Thread | None = None

    @contextmanager
    def monitor_process(self, process):
        try:
            self.start_monitoring(process)
            yield process
        finally:
            self.stop_monitoring()

    def start_monitoring(self, process):
        self.reset()
        self.start_time = time.time()
        self.monitoring = True

        def tree_rss_mb(root: psutil.Process) -> float:
            # Both tools shell out to a resolver (uv / pip); sampling only the
            # root process undercounts memory by the child's whole footprint.
            procs = [root, *root.children(recursive=True)]
            total = 0
            for proc in procs:
                try:
                    total += proc.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return total / (1024 * 1024)

        def monitor():
            try:
                ps_process = psutil.Process(process.pid)
            except psutil.NoSuchProcess:
                return

            while self.monitoring and process.poll() is None:
                try:
                    self.peak_memory = max(self.peak_memory, tree_rss_mb(ps_process))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                time.sleep(self.sample_interval)

        self._monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.end_time = time.time()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)

    def elapsed(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


def format_memory(memory_mb: float) -> str:
    if memory_mb >= 1024:
        return f"{memory_mb / 1024:.2f} GB"
    return f"{memory_mb:.2f} MB"


def format_time(seconds: float) -> str:
    if seconds >= 60:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"
    return f"{seconds:.3f}s"
