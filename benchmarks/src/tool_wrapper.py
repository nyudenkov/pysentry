import json
import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .performance_monitor import PerformanceMonitor, RunResult

# Dataset modes decide which comparison a tool is set up for:
#   "resolve"    - unpinned requirements, dependency resolution ON (real-world).
#   "audit-only" - pinned requirements, resolution OFF on both tools, so the
#                  number is pure audit throughput with resolver choice removed.
MODE_RESOLVE = "resolve"
MODE_AUDIT_ONLY = "audit-only"


@dataclass
class BenchmarkConfig:
    tool_name: str
    config_name: str
    command_args: list[str]  # static part; cache/env/path appended at run time


class ToolWrapper(ABC):
    def __init__(self, name: str):
        self.name = name
        self.monitor = PerformanceMonitor()

    @abstractmethod
    def check_availability(self) -> bool:
        pass

    @abstractmethod
    def get_benchmark_configs(
        self, requirements_file: Path, mode: str
    ) -> list[BenchmarkConfig]:
        pass

    @abstractmethod
    def count_vulns(self, stdout: str) -> tuple[int, int]:
        """(raw, canonical): the count the tool printed, and the distinct count
        after collapsing advisory aliases. (-1, -1) if stdout can't be parsed."""

    def execute(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        working_dir: Path | None = None,
        cache_type: str = "hot",
    ) -> RunResult:
        if working_dir is None:
            working_dir = requirements_file.parent

        cmd = self._prepare_command(config, requirements_file, cache_type)

        try:
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

            if process.returncode > 1:
                print(f"    ✗ Command failed with exit code {process.returncode}")
                for label, stream in (("STDERR", stderr), ("STDOUT", stdout)):
                    if stream:
                        print(f"    ✗ {label}:")
                        for line in stream.split("\n"):
                            if line.strip():
                                print(f"      {line}")

            if process.returncode <= 1:
                raw, canonical = self.count_vulns(stdout)
            else:
                raw, canonical = -1, -1

            return RunResult(
                execution_time=self.monitor.elapsed(),
                peak_memory_mb=self.monitor.peak_memory,
                exit_code=process.returncode,
                raw_vulns=raw,
                canonical_vulns=canonical,
                stdout=stdout,
                stderr=stderr,
            )

        except Exception as e:
            return RunResult(
                execution_time=0.0,
                peak_memory_mb=0.0,
                exit_code=-1,
                raw_vulns=-1,
                canonical_vulns=-1,
                stdout="",
                stderr=f"Execution failed: {e!s}",
            )

    @abstractmethod
    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        cache_type: str,
    ) -> list[str]:
        pass

    def _get_env(self) -> dict[str, str] | None:
        return None

    @abstractmethod
    def clear_cache(self):
        pass

    @abstractmethod
    def version(self) -> str:
        pass


class PySentryWrapper(ToolWrapper):
    def __init__(self, binary_path: Path | None = None, cache_dir: Path | None = None):
        super().__init__("pysentry")
        self.binary_path = binary_path or self._find_binary()
        self.cache_dir = cache_dir

    def _find_binary(self) -> Path | None:
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

    def version(self) -> str:
        try:
            result = subprocess.run(
                [str(self.binary_path), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip().split()[-1]
        except Exception:
            pass
        return "unknown"

    def get_benchmark_configs(
        self, requirements_file: Path, mode: str
    ) -> list[BenchmarkConfig]:
        # Only the resolver knob differs between modes; the source matrix is shared,
        # so the speed-vs-coverage tradeoff per source is visible on the pinned input.
        resolver = (
            ["--no-resolver"] if mode == MODE_AUDIT_ONLY else ["--resolver", "uv"]
        )

        def build(name: str, source: str, maintenance: bool) -> BenchmarkConfig:
            args = [str(self.binary_path), "--format", "json", *resolver]
            args += ["--sources", source]
            # pip-audit does no PEP 792 maintenance checks, and those per-package
            # index calls dominate pysentry's cold time (~91%). Off = fair
            # vuln-vs-vuln; the one maintenance-on config shows the feature's cost.
            if not maintenance:
                args += ["--no-maintenance-check"]
            return BenchmarkConfig(
                tool_name="pysentry", config_name=name, command_args=args
            )

        sources = [
            ("pypa", "pypa"),
            ("osv", "osv"),
            ("pypi", "pypi"),
            ("all-sources", "pypa,osv,pypi"),
        ]
        configs = [
            build(f"pysentry-{name}", src, maintenance=False) for name, src in sources
        ]
        configs.append(build("pysentry-pypi-maintenance", "pypi", maintenance=True))
        return configs

    def count_vulns(self, stdout: str) -> tuple[int, int]:
        # pysentry may append a version-update notice after the JSON, so decode
        # just the leading JSON value instead of the whole stream. pysentry dedupes
        # aliases natively (v0.4.8+), so raw ≈ canonical here — unlike pip-audit.
        try:
            data, _ = json.JSONDecoder().raw_decode(stdout.lstrip())
            entries = [
                (v["package_name"], {v["id"], *(v.get("aliases") or [])})
                for v in data["vulnerabilities"]
            ]
            return int(data["total_vulnerabilities"]), canonical_vuln_count(entries)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return -1, -1

    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        cache_type: str,
    ) -> list[str]:
        cmd = config.command_args.copy()

        if self.cache_dir:
            cmd.extend(["--cache-dir", str(self.cache_dir)])

        if cache_type == "cold":
            cmd.append("--no-cache")

        cmd.append(str(requirements_file.parent))
        return cmd

    def clear_cache(self):
        _clear_dir_contents(self.cache_dir)


class PipAuditWrapper(ToolWrapper):
    def __init__(self, cache_dir: Path | None = None):
        super().__init__("pip-audit")
        self.cache_dir = cache_dir

    def _pip_cache(self) -> Path | None:
        # Controlled PIP_CACHE_DIR so a cold run really is cold: pysentry's
        # --no-cache wipes everything, so pip's wheel cache must be wiped too.
        return self.cache_dir / "pip-wheel-cache" if self.cache_dir else None

    def check_availability(self) -> bool:
        try:
            result = subprocess.run(
                ["pip-audit", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def version(self) -> str:
        try:
            result = subprocess.run(
                ["pip-audit", "--version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip().split()[-1]
        except Exception:
            pass
        return "unknown"

    def get_benchmark_configs(
        self, requirements_file: Path, mode: str
    ) -> list[BenchmarkConfig]:
        base = ["pip-audit", "--format", "json"]
        # --no-deps --disable-pip = audit the pinned set with no resolution.
        no_resolve = ["--no-deps", "--disable-pip"] if mode == MODE_AUDIT_ONLY else []
        # -s pypi / -s osv is pip-audit's coverage knob, mirroring pysentry's sources.
        return [
            BenchmarkConfig(
                tool_name="pip-audit",
                config_name=f"pip-audit-{service}",
                command_args=[*base, "-s", service, *no_resolve, "--requirement"],
            )
            for service in ["pypi", "osv"]
        ]

    def count_vulns(self, stdout: str) -> tuple[int, int]:
        # raw = advisory entries pip-audit printed (its OSV service does NOT collapse
        # aliases, so this over-reports); canonical = distinct after alias collapse.
        try:
            data = json.loads(stdout)
            entries = [
                (dep["name"], {vuln["id"], *(vuln.get("aliases") or [])})
                for dep in data.get("dependencies", [])
                for vuln in dep.get("vulns", [])
            ]
            return len(entries), canonical_vuln_count(entries)
        except (json.JSONDecodeError, KeyError, AttributeError, TypeError):
            return -1, -1

    def _prepare_command(
        self,
        config: BenchmarkConfig,
        requirements_file: Path,
        cache_type: str,
    ) -> list[str]:
        cmd = config.command_args.copy()
        cmd.append(str(requirements_file))

        if self.cache_dir:
            cmd.extend(["--cache-dir", str(self.cache_dir / "pip-audit")])
        return cmd

    def _get_env(self) -> dict[str, str] | None:
        pip_cache = self._pip_cache()
        if not pip_cache:
            return None
        return {**os.environ, "PIP_CACHE_DIR": str(pip_cache)}

    def clear_cache(self):
        if self.cache_dir:
            _clear_dir(self.cache_dir / "pip-audit")
            _clear_dir(self._pip_cache())
            return
        # No controlled cache dir: fall back to the platform default location.
        defaults = [Path.home() / ".cache" / "pip-audit"]
        if sys.platform == "darwin":
            defaults.append(Path.home() / "Library" / "Caches" / "pip-audit")
        for cache_dir in defaults:
            if cache_dir.exists():
                shutil.rmtree(cache_dir)
                print(f"Cleared pip-audit default cache: {cache_dir}")
                break


def canonical_vuln_count(entries: list[tuple[str, set[str]]]) -> int:
    """Distinct vulnerabilities after collapsing advisory aliases within each
    package. `entries` is (package_name, {id, *aliases}) per raw advisory. Tools
    and sources report the same flaw under different IDs (GHSA/PYSEC/CVE); union
    them so counts are comparable across configs and across tools.
    """
    by_package: dict[str, list[set[str]]] = {}
    for package, ids in entries:
        by_package.setdefault(package, []).append(set(ids))

    total = 0
    for groups in by_package.values():
        components: list[set[str]] = []
        for ids in groups:
            overlapping = [c for c in components if c & ids]
            merged = set(ids)
            for c in overlapping:
                merged |= c
                components.remove(c)
            components.append(merged)
        total += len(components)
    return total


def _clear_dir(path: Path | None):
    if path and path.exists():
        shutil.rmtree(path)


def _clear_dir_contents(path: Path | None):
    if not path or not path.exists():
        return
    for entry in path.glob("*"):
        if entry.is_file():
            entry.unlink()
        else:
            shutil.rmtree(entry)


class ToolRegistry:
    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir
        self.tools: dict[str, ToolWrapper] = {}
        self._register_tools()

    def _register_tools(self):
        for wrapper in (
            PySentryWrapper(cache_dir=self.cache_dir),
            PipAuditWrapper(cache_dir=self.cache_dir),
        ):
            if wrapper.check_availability():
                self.tools[wrapper.name] = wrapper

    def get_available_tools(self) -> list[str]:
        return list(self.tools.keys())

    def get_tool(self, name: str) -> ToolWrapper | None:
        return self.tools.get(name)

    def get_all_benchmark_configs(
        self, requirements_file: Path, mode: str
    ) -> list[BenchmarkConfig]:
        configs = []
        for tool in self.tools.values():
            configs.extend(tool.get_benchmark_configs(requirements_file, mode))
        return configs

    def ensure_pysentry_built(self) -> bool:
        if "pysentry" in self.tools:
            return True
        try:
            project_root = Path(__file__).parent.parent.parent
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
            print(f"Build failed: {result.stderr}")
            return False
        except Exception as e:
            print(f"Build error: {e}")
            return False

    def clear_all_caches(self):
        print("Clearing all tool caches...")
        for tool in self.tools.values():
            tool.clear_cache()
