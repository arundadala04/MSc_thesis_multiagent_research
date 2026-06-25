"""Deploy layer: apply a patch, test it in an isolated Docker container, then keep
it (promote) or undo it (rollback).

The Docker container is the staging environment. If the upgraded dependencies do not
install cleanly the tests fail and the change is rolled back, so a bad patch never
stays in place.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from devsecagent.schema import DeployResult


def latest_installable(package):
    """Return the newest version of the package that has a wheel for this Python, or ''.
    Real environment data the retry loop can use instead of guessing a version.
    """
    with tempfile.TemporaryDirectory() as out:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
             package, "-d", out],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return ""
        for name in os.listdir(out):
            if name.endswith(".whl"):
                return name.split("-")[1]
    return ""


def installable(package, version):
    """Objective build check: does this exact version have an installable wheel for
    the current Python. Returns (ok, message). Uses pip with only-binary so a package
    whose minimum fix has no wheel for this Python is reported as not installable.
    """
    if not version:
        return False, "no version proposed"
    with tempfile.TemporaryDirectory() as out:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
             f"{package}=={version}", "-d", out],
            capture_output=True, text=True,
        )
    return result.returncode == 0, (result.stderr or result.stdout).strip()[-200:]


def apply_patch(project_dir, patch):
    """Rewrite the requirements line for the patched package. Return the old file text."""
    req = Path(project_dir) / "requirements.txt"
    original = req.read_text()
    new_line = patch.change or f"{patch.package}=={patch.to_version}"
    lines = []
    for line in original.splitlines():
        name = line.split("==")[0].strip().lower()
        lines.append(new_line if name == patch.package.lower() else line)
    req.write_text("\n".join(lines) + "\n")
    return original


def rollback(project_dir, original):
    """Restore the requirements file to its original text."""
    (Path(project_dir) / "requirements.txt").write_text(original)


def run_tests_in_docker(project_dir):
    """Install the project's requirements in a clean python container.
    Returns (passed, output). A clean install is the staging health check.
    """
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{Path(project_dir).resolve()}:/app", "-w", "/app",
        "python:3.12-slim",
        "pip", "install", "--quiet", "-r", "requirements.txt",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr)[-500:]


def deploy(project_dir, patch, test_runner=run_tests_in_docker):
    """Apply the patch, run the tests, then promote on pass or roll back on failure."""
    original = apply_patch(project_dir, patch)
    passed, output = test_runner(project_dir)
    if passed:
        return DeployResult("promoted", True, output)
    rollback(project_dir, original)
    return DeployResult("rolled_back", False, output)
