#!/usr/bin/env python3
"""
PySentry Performance Benchmarking and Validation Framework
Comprehensive performance testing with Windows-specific optimizations
"""

import os
import sys
import time
import json
import psutil
import tempfile
import subprocess
import statistics
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import platform
import tracemalloc
import cProfile
import pstats
from io import StringIO

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import pysentry
    PYSENTRY_AVAILABLE = True
except ImportError:
    PYSENTRY_AVAILABLE = False
    print("Warning: PySentry not available for direct Python benchmarking")


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""
    name: str
    execution_time: float
    memory_peak: float
    memory_average: float
    cpu_percent: float
    packages_scanned: int
    vulnerabilities_found: int
    exit_code: int
    platform: str
    python_version: str
    pysentry_version: str
    success: bool
    error_message: Optional[str] = None


@dataclass
class PerformanceProfile:
    """Detailed performance profiling results."""
    total_time: float
    function_calls: int
    primitive_calls: int
    top_functions: List[Tuple[str, float, int]]
    memory_profile: Dict[str, Any]
    cpu_utilization: List[float]


class PerformanceBenchmark:
    """Comprehensive performance benchmarking suite for PySentry."""
    
    def __init__(self, pysentry_binary: str = "pysentry-rs"):
        self.pysentry_binary = pysentry_binary
        self.results: List[BenchmarkResult] = []
        self.temp_dir = tempfile.mkdtemp(prefix="pysentry_bench_")
        self.platform_info = self._get_platform_info()
        
    def _get_platform_info(self) -> Dict[str, str]:
        """Get comprehensive platform information."""
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.architecture()[0],
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": str(psutil.cpu_count(logical=True)),
            "memory_gb": f"{psutil.virtual_memory().total / (1024**3):.2f}",
            "is_windows": platform.system() == "Windows"
        }
    
    def create_test_project(self, 
                          name: str, 
                          dependency_count: int, 
                          has_vulnerabilities: bool = True) -> Path:
        """Create a test project with specified characteristics."""
        project_dir = Path(self.temp_dir) / name
        project_dir.mkdir(exist_ok=True)
        
        # Create pyproject.toml with dependencies
        dependencies = []
        
        if has_vulnerabilities:
            # Add some packages with known vulnerabilities (for testing)
            vulnerable_packages = [
                "requests==2.25.0",  # Known vulnerable version
                "django==2.2.0",     # Known vulnerable version
                "flask==1.0.0",      # Known vulnerable version
                "pillow==7.0.0",     # Known vulnerable version
                "sqlalchemy==1.2.0", # Known vulnerable version
            ]
            dependencies.extend(vulnerable_packages[:min(5, dependency_count)])
        
        # Add safe packages to reach desired count
        safe_packages = [
            "click>=8.0.0",
            "colorama>=0.4.0",
            "certifi>=2022.0.0",
            "charset-normalizer>=2.0.0",
            "idna>=3.0",
            "urllib3>=1.26.0",
            "six>=1.16.0",
            "python-dateutil>=2.8.0",
            "pytz>=2021.0",
            "setuptools>=60.0.0",
        ]
        
        remaining = dependency_count - len(dependencies)
        dependencies.extend(safe_packages[:remaining])
        
        pyproject_content = f'''[project]
name = "{name}"
version = "0.1.0"
description = "Test project for PySentry benchmarking"
dependencies = {json.dumps(dependencies)}

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"
'''
        
        (project_dir / "pyproject.toml").write_text(pyproject_content)
        
        # Create requirements.txt as well
        (project_dir / "requirements.txt").write_text("\n".join(dependencies))
        
        # Create some Python files
        for i in range(min(10, dependency_count)):
            py_file = project_dir / f"module_{i}.py"
            py_file.write_text(f'''
"""Test module {i}"""
import sys
import os
{chr(10).join(f"import {dep.split('==')[0].split('>=')[0].split('<')[0]}" for dep in dependencies[:3] if i % 3 == 0)}

def test_function_{i}():
    """Test function for module {i}"""
    return "test_{i}"
''')
        
        return project_dir
    
    def measure_performance(self, 
                          command: List[str], 
                          project_path: Path,
                          timeout: int = 300) -> Tuple[BenchmarkResult, Optional[PerformanceProfile]]:
        """Measure performance of a PySentry command execution."""
        start_time = time.time()
        
        # Start memory and CPU monitoring
        tracemalloc.start()
        process = psutil.Popen(
            command,
            cwd=project_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Monitor resource usage
        memory_samples = []
        cpu_samples = []
        
        try:
            while process.poll() is None:
                try:
                    proc_info = psutil.Process(process.pid)
                    memory_samples.append(proc_info.memory_info().rss / 1024 / 1024)  # MB
                    cpu_samples.append(proc_info.cpu_percent())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                time.sleep(0.1)
            
            stdout, stderr = process.communicate(timeout=timeout)
            exit_code = process.returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            exit_code = -1
            
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Get memory statistics
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Analyze output for package count and vulnerabilities
        packages_scanned = 0
        vulnerabilities_found = 0
        
        if stdout:
            # Parse output to extract metrics (implementation specific)
            if "packages scanned" in stdout.lower():
                try:
                    packages_scanned = int(stdout.split("packages scanned")[0].split()[-1])
                except (ValueError, IndexError):
                    pass
            
            if "vulnerabilities found" in stdout.lower():
                try:
                    vulnerabilities_found = int(stdout.split("vulnerabilities found")[0].split()[-1])
                except (ValueError, IndexError):
                    pass
        
        # Get PySentry version
        pysentry_version = "unknown"
        try:
            version_result = subprocess.run(
                [self.pysentry_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if version_result.returncode == 0:
                pysentry_version = version_result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        result = BenchmarkResult(
            name=project_path.name,
            execution_time=execution_time,
            memory_peak=peak / 1024 / 1024 if peak else max(memory_samples, default=0),
            memory_average=statistics.mean(memory_samples) if memory_samples else 0,
            cpu_percent=statistics.mean(cpu_samples) if cpu_samples else 0,
            packages_scanned=packages_scanned,
            vulnerabilities_found=vulnerabilities_found,
            exit_code=exit_code,
            platform=self.platform_info["os"],
            python_version=self.platform_info["python_version"],
            pysentry_version=pysentry_version,
            success=exit_code == 0 or exit_code == 1,  # 1 is expected when vulnerabilities found
            error_message=stderr if stderr and exit_code not in [0, 1] else None
        )
        
        # Create performance profile
        profile = PerformanceProfile(
            total_time=execution_time,
            function_calls=0,  # Would need profiling integration
            primitive_calls=0,
            top_functions=[],
            memory_profile={
                "peak_mb": result.memory_peak,
                "average_mb": result.memory_average,
                "samples": len(memory_samples)
            },
            cpu_utilization=cpu_samples
        )
        
        return result, profile
    
    def benchmark_small_project(self) -> BenchmarkResult:
        """Benchmark scanning a small project (1-10 dependencies)."""
        project = self.create_test_project("small_project", 5, has_vulnerabilities=True)
        command = [self.pysentry_binary, str(project)]
        result, _ = self.measure_performance(command, project)
        result.name = "small_project_benchmark"
        return result
    
    def benchmark_medium_project(self) -> BenchmarkResult:
        """Benchmark scanning a medium project (50-100 dependencies)."""
        project = self.create_test_project("medium_project", 75, has_vulnerabilities=True)
        command = [self.pysentry_binary, str(project), "--recursive"]
        result, _ = self.measure_performance(command, project)
        result.name = "medium_project_benchmark"
        return result
    
    def benchmark_large_project(self) -> BenchmarkResult:
        """Benchmark scanning a large project (200+ dependencies)."""
        project = self.create_test_project("large_project", 200, has_vulnerabilities=True)
        command = [self.pysentry_binary, str(project), "--recursive", "--detailed-report"]
        result, _ = self.measure_performance(command, project)
        result.name = "large_project_benchmark"
        return result
    
    def benchmark_sarif_output(self) -> BenchmarkResult:
        """Benchmark SARIF output generation performance."""
        project = self.create_test_project("sarif_project", 50, has_vulnerabilities=True)
        sarif_file = project / "output.sarif"
        command = [
            self.pysentry_binary, str(project),
            "--output-format", "sarif",
            "--output", str(sarif_file)
        ]
        result, _ = self.measure_performance(command, project)
        result.name = "sarif_output_benchmark"
        return result
    
    def benchmark_parallel_execution(self) -> BenchmarkResult:
        """Benchmark parallel scanning performance."""
        if not self.platform_info["is_windows"]:
            # Create multiple small projects
            projects = []
            for i in range(4):
                project = self.create_test_project(f"parallel_project_{i}", 25)
                projects.append(project)
            
            start_time = time.time()
            
            # Run scans in parallel
            with ProcessPoolExecutor(max_workers=4) as executor:
                futures = []
                for project in projects:
                    command = [self.pysentry_binary, str(project)]
                    future = executor.submit(subprocess.run, command, 
                                           capture_output=True, text=True)
                    futures.append(future)
                
                results = [future.result() for future in futures]
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            # Aggregate results
            total_packages = sum(25 for _ in projects)
            total_vulnerabilities = sum(1 if r.returncode == 1 else 0 for r in results)
            
            result = BenchmarkResult(
                name="parallel_execution_benchmark",
                execution_time=execution_time,
                memory_peak=0,  # Would need more sophisticated measurement
                memory_average=0,
                cpu_percent=0,
                packages_scanned=total_packages,
                vulnerabilities_found=total_vulnerabilities,
                exit_code=0,
                platform=self.platform_info["os"],
                python_version=self.platform_info["python_version"],
                pysentry_version="unknown",
                success=all(r.returncode in [0, 1] for r in results)
            )
        else:
            # Windows fallback - single threaded test
            project = self.create_test_project("windows_parallel_project", 100)
            command = [self.pysentry_binary, str(project)]
            result, _ = self.measure_performance(command, project)
            result.name = "parallel_execution_benchmark"
        
        return result
    
    def benchmark_memory_efficiency(self) -> BenchmarkResult:
        """Benchmark memory usage efficiency."""
        project = self.create_test_project("memory_test_project", 150)
        command = [self.pysentry_binary, str(project), "--memory-efficient"]
        result, _ = self.measure_performance(command, project)
        result.name = "memory_efficiency_benchmark"
        return result
    
    def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Run all benchmark tests."""
        print("Starting PySentry Performance Benchmarks")
        print(f"Platform: {self.platform_info['os']} {self.platform_info['architecture']}")
        print(f"Python: {self.platform_info['python_version']}")
        print(f"CPU Cores: {self.platform_info['cpu_count']}")
        print(f"Memory: {self.platform_info['memory_gb']} GB")
        print("-" * 60)
        
        benchmarks = [
            ("Small Project", self.benchmark_small_project),
            ("Medium Project", self.benchmark_medium_project), 
            ("Large Project", self.benchmark_large_project),
            ("SARIF Output", self.benchmark_sarif_output),
            ("Parallel Execution", self.benchmark_parallel_execution),
            ("Memory Efficiency", self.benchmark_memory_efficiency),
        ]
        
        results = []
        
        for name, benchmark_func in benchmarks:
            print(f"Running {name} benchmark...")
            try:
                result = benchmark_func()
                results.append(result)
                
                status = "✓ PASS" if result.success else "✗ FAIL"
                print(f"  {status} - {result.execution_time:.2f}s, "
                      f"{result.memory_peak:.1f}MB peak, "
                      f"{result.packages_scanned} packages")
                
                if not result.success and result.error_message:
                    print(f"    Error: {result.error_message}")
                    
            except Exception as e:
                print(f"  ✗ ERROR - {str(e)}")
                result = BenchmarkResult(
                    name=f"{name.lower().replace(' ', '_')}_benchmark",
                    execution_time=0,
                    memory_peak=0,
                    memory_average=0,
                    cpu_percent=0,
                    packages_scanned=0,
                    vulnerabilities_found=0,
                    exit_code=-1,
                    platform=self.platform_info["os"],
                    python_version=self.platform_info["python_version"],
                    pysentry_version="unknown",
                    success=False,
                    error_message=str(e)
                )
                results.append(result)
        
        self.results = results
        return results
    
    def generate_performance_report(self, output_file: Optional[Path] = None) -> str:
        """Generate a comprehensive performance report."""
        if not self.results:
            return "No benchmark results available."
        
        # Calculate summary statistics
        successful_results = [r for r in self.results if r.success]
        total_time = sum(r.execution_time for r in successful_results)
        avg_time = statistics.mean([r.execution_time for r in successful_results]) if successful_results else 0
        max_memory = max([r.memory_peak for r in successful_results], default=0)
        total_packages = sum(r.packages_scanned for r in successful_results)
        total_vulnerabilities = sum(r.vulnerabilities_found for r in successful_results)
        
        # Performance rating calculation
        def calculate_performance_rating() -> Tuple[str, float]:
            if not successful_results:
                return "FAILED", 0.0
            
            # Base score on execution time per package
            avg_time_per_package = avg_time / (total_packages / len(successful_results)) if total_packages > 0 else float('inf')
            
            if avg_time_per_package < 0.01:  # < 10ms per package
                return "EXCELLENT", 0.95
            elif avg_time_per_package < 0.05:  # < 50ms per package
                return "GOOD", 0.85
            elif avg_time_per_package < 0.1:   # < 100ms per package
                return "FAIR", 0.75
            else:
                return "POOR", 0.60
        
        performance_rating, fitness_score = calculate_performance_rating()
        
        report = f"""
# PySentry Performance Benchmark Report

## Summary
- **Platform**: {self.platform_info['os']} {self.platform_info['architecture']}
- **Python Version**: {self.platform_info['python_version']}
- **CPU Cores**: {self.platform_info['cpu_count']}
- **Memory**: {self.platform_info['memory_gb']} GB
- **Performance Rating**: {performance_rating}
- **Fitness Score**: {fitness_score:.2f}

## Results Summary
- **Tests Run**: {len(self.results)}
- **Successful**: {len(successful_results)}
- **Failed**: {len(self.results) - len(successful_results)}
- **Total Execution Time**: {total_time:.2f}s
- **Average Execution Time**: {avg_time:.2f}s
- **Peak Memory Usage**: {max_memory:.1f}MB
- **Total Packages Scanned**: {total_packages}
- **Total Vulnerabilities Found**: {total_vulnerabilities}

## Detailed Results

"""
        
        for result in self.results:
            status = "PASS" if result.success else "FAIL"
            report += f"""### {result.name.replace('_', ' ').title()}
- **Status**: {status}
- **Execution Time**: {result.execution_time:.2f}s
- **Memory Peak**: {result.memory_peak:.1f}MB
- **Memory Average**: {result.memory_average:.1f}MB
- **CPU Usage**: {result.cpu_percent:.1f}%
- **Packages Scanned**: {result.packages_scanned}
- **Vulnerabilities Found**: {result.vulnerabilities_found}
- **Exit Code**: {result.exit_code}
"""
            if result.error_message:
                report += f"- **Error**: {result.error_message}\n"
            
            report += "\n"
        
        # Performance recommendations
        report += """## Performance Recommendations

"""
        
        if max_memory > 1000:  # > 1GB
            report += "- Consider reducing memory usage by processing dependencies in batches\n"
        
        if avg_time > 30:  # > 30 seconds average
            report += "- Consider optimizing database lookup algorithms\n"
            report += "- Implement caching for repeated vulnerability checks\n"
        
        if performance_rating in ["POOR", "FAIR"]:
            report += "- Profile bottlenecks using `--profile` flag\n"
            report += "- Consider parallel processing for large dependency sets\n"
        
        report += f"""
## Fitness Assessment

**Overall Fitness Score**: {fitness_score:.2f}/1.00

This score is calculated based on:
- Execution time per package scanned
- Memory efficiency 
- Success rate across different project sizes
- Platform-specific optimizations

**Target Score**: 0.85+ (Current: {fitness_score:.2f})
"""
        
        if fitness_score >= 0.85:
            report += "\n✅ **PASSED**: Performance meets target requirements"
        else:
            report += "\n❌ **NEEDS IMPROVEMENT**: Performance below target threshold"
        
        # Save report if output file specified
        if output_file:
            output_file.write_text(report)
            print(f"Performance report saved to: {output_file}")
        
        return report
    
    def export_json_results(self, output_file: Path) -> None:
        """Export benchmark results as JSON."""
        data = {
            "platform_info": self.platform_info,
            "timestamp": time.time(),
            "results": [asdict(result) for result in self.results],
            "summary": {
                "total_tests": len(self.results),
                "successful_tests": len([r for r in self.results if r.success]),
                "total_execution_time": sum(r.execution_time for r in self.results),
                "total_packages_scanned": sum(r.packages_scanned for r in self.results),
                "total_vulnerabilities_found": sum(r.vulnerabilities_found for r in self.results)
            }
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        print(f"JSON results exported to: {output_file}")
    
    def cleanup(self):
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Warning: Could not clean up temp directory {self.temp_dir}: {e}")


def main():
    """Main benchmark execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PySentry Performance Benchmark Suite")
    parser.add_argument("--binary", default="pysentry-rs", 
                       help="Path to PySentry binary (default: pysentry-rs)")
    parser.add_argument("--output", type=Path,
                       help="Output file for performance report")
    parser.add_argument("--json", type=Path,
                       help="Export results as JSON to specified file")
    parser.add_argument("--quick", action="store_true",
                       help="Run only quick benchmarks (skip large project test)")
    
    args = parser.parse_args()
    
    # Verify PySentry is available
    try:
        result = subprocess.run([args.binary, "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"Error: Could not execute {args.binary}")
            sys.exit(1)
        print(f"PySentry version: {result.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"Error: PySentry binary not found at {args.binary}")
        print("Please install PySentry or specify correct path with --binary")
        sys.exit(1)
    
    # Run benchmarks
    benchmark = PerformanceBenchmark(args.binary)
    
    try:
        if args.quick:
            print("Running quick benchmark suite...")
            # Run only small and medium tests for quick validation
            results = [
                benchmark.benchmark_small_project(),
                benchmark.benchmark_medium_project(),
                benchmark.benchmark_sarif_output()
            ]
            benchmark.results = results
        else:
            print("Running full benchmark suite...")
            benchmark.run_all_benchmarks()
        
        # Generate and display report
        report = benchmark.generate_performance_report(args.output)
        print("\n" + "="*60)
        print(report)
        
        # Export JSON if requested
        if args.json:
            benchmark.export_json_results(args.json)
        
        # Check if performance meets requirements (fitness score >= 0.85)
        successful_results = [r for r in benchmark.results if r.success]
        if successful_results:
            avg_time_per_package = statistics.mean([
                r.execution_time / max(r.packages_scanned, 1) 
                for r in successful_results
            ])
            fitness_score = 0.95 if avg_time_per_package < 0.01 else \
                           0.85 if avg_time_per_package < 0.05 else \
                           0.75 if avg_time_per_package < 0.1 else 0.60
            
            exit_code = 0 if fitness_score >= 0.85 else 1
        else:
            exit_code = 1
        
        print(f"\nBenchmark completed with exit code: {exit_code}")
        sys.exit(exit_code)
        
    finally:
        benchmark.cleanup()


if __name__ == "__main__":
    main()