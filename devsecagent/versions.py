"""Version comparison, used to check a patch reaches the scanner's fixed version."""
from packaging.version import InvalidVersion, Version


def at_least(version, target):
    """True if version >= target by semantic version order, False if either is invalid."""
    try:
        return Version(str(version)) >= Version(str(target))
    except InvalidVersion:
        return False
