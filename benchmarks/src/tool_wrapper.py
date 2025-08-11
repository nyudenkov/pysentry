import subprocess
import shutil
import tempfile
import sys
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Optional, Dict
from dataclasses import dataclass

from .performance_monitor import PerformanceMonitor, PerformanceMetrics


@dataclass
class BenchmarkConfig:
    tool_name: str
    config_name: str
    command_args: List[str]
    requires_build: bool = False


class ToolWrapper(ABC):
    def __init__(self, name: str):
        self.name = name
        self.monitor = PerformanceMonitor()

    @abstractmethod
    def check_availability(self) -> bool:
        pass

    @abstractmethod
    def get_benchmark_configs(self, requirements_file: Path) -> List[BenchmarkConfig]:
        pass

    def execute(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        use_cache: bool = True,
        working_dir: Optional[Path] = None,
        dataset_name: str = "",
        cache_type: str = "hot",
    ) -> PerformanceMetrics:
        if working_dir is None:
            working_dir = requirements_file.parent

        cmd = self._prepare_command(
            config, requirements_file, use_cache, dataset_name, cache_type
        )

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                if working_dir and working_dir.exists():
                    print(f"    Command: {' '.join(cmd)}")
                    print(f"    Working dir: {working_dir}")

                process = subprocess.Popen(
                    cmd,
                    cwd=working_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=self._get_env(),
                )

                with self.monitor.monitor_process(process):
                    stdout, stderr = process.communicate()

                if process.returncode != 0:
                    print(f"    ✗ Command failed with exit code {process.returncode}")
                    if stderr:
                        print("    ✗ STDERR:")
                        for line in stderr.split("\n"):
                            if line.strip():
                                print(f"      {line}")
                    if stdout:
                        print("    ✗ STDOUT:")
                        for line in stdout.split("\n"):
                            if line.strip():
                                print(f"      {line}")

                return self.monitor.get_metrics(process.returncode, stdout, stderr)

        except Exception as e:
            return PerformanceMetrics(
                execution_time=0.0,
                peak_memory_mb=0.0,
                avg_memory_mb=0.0,
                cpu_percent=0.0,
                exit_code=-1,
                stdout="",
                stderr=f"Execution failed: {str(e)}",
            )

    @abstractmethod
    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        use_cache: bool,
        dataset_name: str = "",
        cache_type: str = "hot",
    ) -> List[str]:
        pass

    def _get_env(self) -> Optional[Dict[str, str]]:
        return None


class PySentryWrapper(ToolWrapper):
    def __init__(
        self, binary_path: Optional[Path] = None, cache_dir: Optional[Path] = None
    ):
        super().__init__("pysentry")
        self.binary_path = binary_path or self._find_binary()
        self.cache_dir = cache_dir

    def _find_binary(self) -> Optional[Path]:
        benchmark_dir = Path(__file__).parent.parent
        relative_binary = benchmark_dir.parent / "target" / "release" / "pysentry"

        if relative_binary.exists():
            return relative_binary

        system_binary = shutil.which("pysentry")
        if system_binary:
            return Path(system_binary)

        return None

    def check_availability(self) -> bool:
        if not self.binary_path or not self.binary_path.exists():
            return False

        try:
            result = subprocess.run(
                [str(self.binary_path), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_benchmark_configs(self, requirements_file: Path) -> List[BenchmarkConfig]:
        base_args = [str(self.binary_path), "--format", "json", "--resolver", "uv"]

        configs = []

        for source in ["pypa", "osv", "pypi"]:
            configs.append(
                BenchmarkConfig(
                    tool_name="pysentry",
                    config_name=f"pysentry-{source}",
                    command_args=base_args + ["--sources", source],
                    requires_build=False,
                )
            )

        configs.append(
            BenchmarkConfig(
                tool_name="pysentry",
                config_name="pysentry-all-sources",
                command_args=base_args + ["--sources", "pypa,osv,pypi"],
                requires_build=False,
            )
        )

        return configs

    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        use_cache: bool,
        dataset_name: str = "",
        cache_type: str = "hot",
    ) -> List[str]:
        """Prepare PySentry command."""
        cmd = config.command_args.copy()

        if self.cache_dir:
            cmd.extend(["--cache-dir", str(self.cache_dir)])

        if cache_type == "cold":
            cmd.append("--no-cache")
            print(f"  [PySentry {cache_type} run] Disabling ALL caches")
        else:
            print(f"  [PySentry {cache_type} run] Using ALL caches")

        cmd.append(str(requirements_file.parent))

        return cmd

    def clear_cache(self):
        if self.cache_dir and self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
                elif cache_file.is_dir():
                    shutil.rmtree(cache_file)
            print(f"Cleared PySentry cache: {self.cache_dir}")


class PipAuditWrapper(ToolWrapper):
    def __init__(self, cache_dir: Optional[Path] = None):
        super().__init__("pip-audit")
        self.cache_dir = cache_dir

    def check_availability(self) -> bool:
        try:
            result = subprocess.run(
                ["pip-audit", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_benchmark_configs(self, requirements_file: Path) -> List[BenchmarkConfig]:
        return [
            BenchmarkConfig(
                tool_name="pip-audit",
                config_name="pip-audit-default",
                command_args=["pip-audit", "--format", "json", "--requirement"],
                requires_build=False,
            )
        ]

    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        use_cache: bool,
        dataset_name: str = "",
        cache_type: str = "hot",
    ) -> List[str]:
        cmd = config.command_args.copy()

        cmd.append(str(requirements_file))

        if self.cache_dir:
            pip_audit_cache = self.cache_dir / "pip-audit"
            cmd.extend(["--cache-dir", str(pip_audit_cache)])
            print(
                f"  [pip-audit {cache_type} run] Using cache directory: {pip_audit_cache}"
            )
        else:
            print(f"  [pip-audit {cache_type} run] Using default cache location")

        return cmd

    def clear_cache(self):
        """Clear pip-audit cache directory."""
        if self.cache_dir:
            pip_audit_cache = self.cache_dir / "pip-audit"
            if pip_audit_cache.exists():
                shutil.rmtree(pip_audit_cache)
                print(f"Cleared pip-audit cache: {pip_audit_cache}")
        else:
            import os
            from pathlib import Path

            possible_cache_dirs = []

            if os.name == "posix":
                possible_cache_dirs.append(Path.home() / ".cache" / "pip-audit")

            if sys.platform == "darwin":
                possible_cache_dirs.append(
                    Path.home() / "Library" / "Caches" / "pip-audit"
                )

            for cache_dir in possible_cache_dirs:
                if cache_dir.exists():
                    shutil.rmtree(cache_dir)
                    print(f"Cleared pip-audit default cache: {cache_dir}")
                    break


class ToolRegistry:
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir
        self.tools: Dict[str, ToolWrapper] = {}
        self._register_tools()

    def _register_tools(self):
        pysentry = PySentryWrapper(cache_dir=self.cache_dir)
        if pysentry.check_availability():
            self.tools["pysentry"] = pysentry

        pip_audit = PipAuditWrapper(cache_dir=self.cache_dir)
        if pip_audit.check_availability():
            self.tools["pip-audit"] = pip_audit

    def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        return list(self.tools.keys())

    def get_tool(self, name: str) -> Optional[ToolWrapper]:
        """Get tool wrapper by name."""
        return self.tools.get(name)

    def get_all_benchmark_configs(
        self, requirements_file: Path
    ) -> List[BenchmarkConfig]:
        configs = []
        for tool in self.tools.values():
            configs.extend(tool.get_benchmark_configs(requirements_file))
        return configs

    def ensure_pysentry_built(self) -> bool:
        pysentry = self.tools.get("pysentry")
        if not pysentry:
            try:
                benchmark_dir = Path(__file__).parent.parent
                project_root = benchmark_dir.parent

                print("Building PySentry...")
                result = subprocess.run(
                    ["cargo", "build", "--release"],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode == 0:
                    self._register_tools()
                    return "pysentry" in self.tools
                else:
                    print(f"Build failed: {result.stderr}")
                    return False

            except Exception as e:
                print(f"Build error: {e}")
                return False

        return True

    def clear_all_caches(self):
        print("Clearing all tool caches...")
        for tool_name, tool in self.tools.items():
            if hasattr(tool, "clear_cache"):
                tool.clear_cache()
            else:
                print(f"Warning: {tool_name} doesn't support cache clearing")
        print("All tool caches cleared")
