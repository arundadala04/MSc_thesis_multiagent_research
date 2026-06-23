"""The patcher: turn a CVE finding into a verified patch.

Two GPT-4o calls. The generator proposes the dependency upgrade, then the verifier
scores it on four checks. The scores are combined into a confidence and routed to
auto, review or manual. Both arms reuse these functions: Arm A runs them once,
Arm B wraps them in a retry loop.
"""
import json

from devsecagent import llm
from devsecagent.schema import Patch

THETA_HIGH = 0.85
THETA_LOW = 0.60

WEIGHTS = {"correctness": 0.35, "completeness": 0.30, "safety": 0.20, "consistency": 0.15}


def parse_json(text):
    """Pull the first JSON object out of an LLM reply."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return {}
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}


def generate_patch(finding, grounding="", temperature=0.0):
    """Ask GPT-4o for the dependency upgrade that fixes the CVE."""
    prompt = (
        "A dependency has a known vulnerability.\n"
        f"CVE: {finding.cve}\n"
        f"Package: {finding.package}\n"
        f"Current version: {finding.version}\n"
        f"Known fixed version from the scanner: {finding.fixed_version}\n"
        f"Ecosystem: {finding.ecosystem}\n"
        f"Reference notes:\n{grounding}\n\n"
        "Give the minimal upgrade that fixes it. Reply as JSON with keys: "
        "to_version (string), change (the new requirements line such as 'PyYAML==5.4'), "
        "explanation (one short sentence)."
    )
    return parse_json(llm.chat(prompt, system="You are a security patching assistant. Reply with JSON only.",
                               temperature=temperature))


def verify_patch(finding, patch_data, grounding=""):
    """Score the patch on four checks and return a confidence from 0 to 1."""
    conf, _ = verify_with_feedback(finding, patch_data, grounding)
    return conf


def verify_with_feedback(finding, patch_data, grounding=""):
    """Like verify_patch but also returns a short note on what to improve next time."""
    prompt = (
        "Review this proposed dependency fix.\n"
        f"CVE: {finding.cve}, package {finding.package}, "
        f"from {finding.version} to {patch_data.get('to_version', '')}.\n"
        f"Scanner says it is fixed in: {finding.fixed_version}.\n"
        f"Reference notes:\n{grounding}\n\n"
        "Score each check from 0 to 1 and reply as JSON with keys: "
        "correctness, completeness, safety, consistency, feedback "
        "(feedback is one short sentence on what to fix if the scores are low)."
    )
    data = parse_json(llm.chat(prompt, system="You are a strict patch reviewer. Reply with JSON only."))
    return confidence(data), str(data.get("feedback", ""))


def confidence(scores):
    """Weighted sum of the four check scores."""
    return round(sum(weight * float(scores.get(name, 0)) for name, weight in WEIGHTS.items()), 3)


def decide(conf):
    """Route on confidence: auto at or above THETA_HIGH, manual below THETA_LOW, else review."""
    if conf >= THETA_HIGH:
        return "auto"
    if conf >= THETA_LOW:
        return "review"
    return "manual"


def make_patch(finding, patch_data, conf, attempts):
    """Build the Patch result object."""
    return Patch(
        cve=finding.cve,
        package=finding.package,
        from_version=finding.version,
        to_version=patch_data.get("to_version", ""),
        change=patch_data.get("change", ""),
        explanation=patch_data.get("explanation", ""),
        confidence=conf,
        decision=decide(conf),
        attempts=attempts,
    )
