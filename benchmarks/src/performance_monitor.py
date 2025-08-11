import time
import psutil
import threading
import platform
from dataclasses import dataclass
from typing import Optional
from contextlib import contextmanager


@dataclass
class PerformanceMetrics:
    execution_time: float  # seconds
    peak_memory_mb: float  # megabytes
    avg_memory_mb: float  # megabytes
    cpu_percent: float  # percentage
    exit_code: int  # process exit code
    stdout: str  # captured stdout
    stderr: str  # captured stderr


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
    def __init__(self, sample_interval: float = 0.1):
        self.sample_interval = sample_interval
        self.reset()

    def reset(self):
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.memory_samples: list[float] = []
        self.cpu_samples: list[float] = []
        self.peak_memory: float = 0.0
        self.monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None

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

        def monitor():
            try:
                ps_process = psutil.Process(process.pid)
            except psutil.NoSuchProcess:
                return

            while self.monitoring and process.poll() is None:
                try:
                    memory_info = ps_process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)
                    self.memory_samples.append(memory_mb)
                    self.peak_memory = max(self.peak_memory, memory_mb)

                    cpu_percent = ps_process.cpu_percent()
                    self.cpu_samples.append(cpu_percent)

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

    def get_metrics(
        self, exit_code: int, stdout: str, stderr: str
    ) -> PerformanceMetrics:
        execution_time = 0.0
        if self.start_time and self.end_time:
            execution_time = self.end_time - self.start_time

        avg_memory = (
            sum(self.memory_samples) / len(self.memory_samples)
            if self.memory_samples
            else 0.0
        )
        avg_cpu = (
            sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0.0
        )

        return PerformanceMetrics(
            execution_time=execution_time,
            peak_memory_mb=self.peak_memory,
            avg_memory_mb=avg_memory,
            cpu_percent=avg_cpu,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )


class BenchmarkTimer:
    def __init__(self):
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, *args):
        self.end_time = time.time()

    @property
    def elapsed_time(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


def format_memory(memory_mb: float) -> str:
    if memory_mb >= 1024:
        return f"{memory_mb / 1024:.2f} GB"
    else:
        return f"{memory_mb:.2f} MB"


def format_time(seconds: float) -> str:
    if seconds >= 60:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"
    else:
        return f"{seconds:.3f}s"
