"""Scanner startup must not depend on engines that were not selected."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def without_asteroid(tmp_path):
    # A fresh interpreter reproduces appliances without the Asteroid submodule,
    # even if other tests have already imported it in the pytest process.
    (tmp_path / "sitecustomize.py").write_text(textwrap.dedent("""
        import importlib.abc
        import sys

        class MissingAsteroid(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "asteroid":
                    raise ModuleNotFoundError("No module named 'asteroid'", name="asteroid")

        sys.meta_path.insert(0, MissingAsteroid())
    """))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(map(str, (
        tmp_path, REPOSITORY_ROOT, REPOSITORY_ROOT / "darkstar",
    )))
    return env


def test_cli_help_without_asteroid(without_asteroid):
    result = subprocess.run(
        [sys.executable, "-m", "darkstar.main", "--help"],
        cwd=REPOSITORY_ROOT, env=without_asteroid,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "--scanner" in result.stdout


@pytest.mark.parametrize("scanner", ["openvas", "zap", "asteroid_normal", "retirejs"])
def test_selected_scanner_without_asteroid(without_asteroid, scanner):
    script = textwrap.dedent("""
        import sys
        from unittest.mock import AsyncMock, Mock, patch
        from darkstar import main

        scanner = sys.argv[1]
        openvas = Mock()
        openvas.return_value.scan_targets = AsyncMock()
        external = Mock()
        with (
            patch.object(main, "register_cli_organization", return_value=("test_org", None)),
            patch.object(main, "get_allowed_scan_targets", return_value=[{"target": "192.0.2.1"}]),
            patch.object(main, "get_asset_scanner_rules", return_value=[]),
            patch.object(main, "OpenVASScanner", openvas),
            patch.object(main, "ExternalVulnerabilityScanner", external),
        ):
            try:
                main.main(["-t", "192.0.2.1", "-d", "test_org", "-s", scanner, "--profile", "selected-profile"])
            except ModuleNotFoundError as error:
                assert scanner in {"asteroid_normal", "retirejs"}
                assert error.name == "asteroid"
            else:
                assert scanner in {"openvas", "zap"}

        if scanner == "openvas":
            openvas.assert_called_once_with(org_name="test_org", config_id="selected-profile")
            openvas.return_value.scan_targets.assert_awaited_once_with(["192.0.2.1"])
            external.assert_not_called()
        elif scanner == "zap":
            external.assert_called_once_with("192.0.2.1", "test_org", profile="selected-profile")
            external.return_value.run_zap.assert_called_once_with()
            openvas.assert_not_called()
        else:
            openvas.assert_not_called()
            external.assert_not_called()
    """)
    result = subprocess.run(
        [sys.executable, "-c", script, scanner],
        cwd=REPOSITORY_ROOT, env=without_asteroid,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
