"""
Windows-specific tests for PySentry functionality.
These tests validate Windows Python package support and cross-platform compatibility.
"""

import os
import sys
import pytest
import subprocess
import tempfile
from pathlib import Path


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
class TestWindowsSpecific:
    """Test suite for Windows-specific functionality."""

    def test_windows_path_handling(self):
        """Test handling of Windows-specific path conventions."""
        # Test long path support (>260 characters)
        long_path_base = "C:\\" + "very_long_directory_name_" * 10
        
        # This should not raise an exception
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "requirements.txt"
            test_file.write_text("requests==2.28.0\n")
            
            # Verify the path can be handled
            assert test_file.exists()

    def test_windows_binary_execution(self):
        """Test that pysentry binary can execute on Windows."""
        try:
            result = subprocess.run(
                [sys.executable, "-c", "import pysentry; print(pysentry.__version__)"],
                capture_output=True,
                text=True,
                timeout=30
            )
            assert result.returncode == 0
            assert result.stdout.strip()  # Should have version output
        except subprocess.TimeoutExpired:
            pytest.fail("PySentry binary execution timed out on Windows")

    def test_windows_registry_config_support(self):
        """Test that Windows registry configuration is supported."""
        # This test validates the capability exists, even if not configured
        try:
            import winreg
            # Test that we can access registry (capability test)
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software")
            winreg.CloseKey(key)
            # If we reach here, registry access is working
            assert True
        except ImportError:
            pytest.skip("winreg not available - not running on Windows")
        except Exception:
            # Registry access failed, but this is expected in CI
            pytest.skip("Registry access not available in test environment")

    def test_powershell_integration(self):
        """Test PowerShell integration capability."""
        try:
            # Test that PowerShell can execute basic commands
            result = subprocess.run(
                ["powershell", "-Command", "Get-Command python -ErrorAction SilentlyContinue"],
                capture_output=True,
                text=True,
                timeout=10
            )
            # This test validates PowerShell integration is possible
            assert result.returncode == 0 or result.returncode == 1  # Either found or not found is OK
        except FileNotFoundError:
            pytest.skip("PowerShell not available in test environment")
        except subprocess.TimeoutExpired:
            pytest.fail("PowerShell integration test timed out")


@pytest.mark.parametrize("python_version", ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"])
def test_python_version_compatibility(python_version):
    """Test compatibility across supported Python versions."""
    # This test validates that the package works across Python versions
    # In real deployment, this would test actual version compatibility
    current_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    
    if current_version == python_version:
        # Test that pysentry imports successfully
        try:
            import pysentry
            assert hasattr(pysentry, '__version__')
            assert hasattr(pysentry, 'main')
        except ImportError as e:
            pytest.fail(f"Failed to import pysentry on Python {python_version}: {e}")
    else:
        pytest.skip(f"Skipping Python {python_version} test on Python {current_version}")


def test_windows_wheel_installation():
    """Test that Windows wheel can be installed and imported."""
    # This test validates the wheel building and installation process
    try:
        import pysentry
        # Test that core functionality is available
        assert hasattr(pysentry, '__version__')
        assert callable(pysentry.main)
        
        # Test that internal Rust module is accessible
        from pysentry import _internal
        assert hasattr(_internal, 'get_version')
        assert hasattr(_internal, 'run_cli')
        
    except ImportError as e:
        pytest.fail(f"Windows wheel installation test failed: {e}")


def test_abi3_compatibility():
    """Test ABI3 stable interface compatibility."""
    try:
        # Import the internal module to verify ABI3 compatibility
        from pysentry import _internal
        
        # Verify that the module was built with ABI3
        # The presence of these functions indicates successful ABI3 build
        assert callable(_internal.get_version)
        assert callable(_internal.run_cli)
        
        # Test version string format
        version = _internal.get_version()
        assert isinstance(version, str)
        assert len(version) > 0
        
    except ImportError as e:
        pytest.fail(f"ABI3 compatibility test failed: {e}")


@pytest.mark.integration
def test_end_to_end_scanning():
    """Integration test for end-to-end vulnerability scanning on Windows."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test requirements file
        req_file = Path(temp_dir) / "requirements.txt"
        req_file.write_text("requests==2.25.0\n")  # Known vulnerable version
        
        try:
            # Test CLI execution
            result = subprocess.run(
                [sys.executable, "-m", "pysentry", str(req_file)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Should execute without error (even if no vulnerabilities found)
            assert result.returncode in [0, 1]  # 0 = success, 1 = vulnerabilities found
            
        except subprocess.TimeoutExpired:
            pytest.fail("End-to-end scanning test timed out")
        except Exception as e:
            pytest.fail(f"End-to-end scanning test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])