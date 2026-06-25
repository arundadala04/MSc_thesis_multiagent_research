"""Tests for the deploy layer."""
import shutil
import subprocess

import pytest

from devsecagent import deployer
from devsecagent.schema import Patch


def _patch():
    return Patch(cve="CVE-2020-14343", package="PyYAML", from_version="5.3.1",
                 to_version="5.4", change="PyYAML==5.4", explanation="upgrade",
                 confidence=0.9, decision="auto", attempts=1)


def _docker_ready():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def test_apply_changes_only_the_target_line(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==5.3.1\nrequests==2.19.1\n")
    deployer.apply_patch(tmp_path, _patch())
    text = req.read_text()
    assert "PyYAML==5.4" in text
    assert "requests==2.19.1" in text


def test_rollback_restores_original(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==5.3.1\nrequests==2.19.1\n")
    original = deployer.apply_patch(tmp_path, _patch())
    deployer.rollback(tmp_path, original)
    assert req.read_text() == "PyYAML==5.3.1\nrequests==2.19.1\n"


def test_deploy_promotes_when_tests_pass(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==5.3.1\n")
    result = deployer.deploy(tmp_path, _patch(), test_runner=lambda d: (True, "ok"))
    assert result.status == "promoted"
    assert "PyYAML==5.4" in req.read_text()


def test_deploy_rolls_back_when_tests_fail(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==5.3.1\n")
    result = deployer.deploy(tmp_path, _patch(), test_runner=lambda d: (False, "conflict"))
    assert result.status == "rolled_back"
    assert req.read_text() == "PyYAML==5.3.1\n"


@pytest.mark.skipif(not _docker_ready(), reason="docker not running")
def test_docker_runner_passes_on_clean_install(tmp_path):
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    passed, _ = deployer.run_tests_in_docker(tmp_path)
    assert passed


@pytest.mark.skipif(not _docker_ready(), reason="docker not running")
def test_docker_runner_fails_on_broken_install(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==9999.0.0\n")
    passed, _ = deployer.run_tests_in_docker(tmp_path)
    assert not passed
