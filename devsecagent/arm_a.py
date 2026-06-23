"""Arm A: the baseline decision core. One generate-then-verify pass, no retry."""
from devsecagent import patcher


def run(finding, grounding=""):
    patch_data = patcher.generate_patch(finding, grounding)
    conf = patcher.verify_patch(finding, patch_data, grounding)
    return patcher.make_patch(finding, patch_data, conf, attempts=1)
