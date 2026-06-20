"""The CVE knowledge base used by the retriever."""
import json
from pathlib import Path

KB_PATH = Path(__file__).parent / "data" / "cve_kb.json"


def load():
    """Return the knowledge base entries (each has cve, package, note)."""
    return json.loads(KB_PATH.read_text())


def documents():
    """Return the entries as plain text, one string per entry, for the retriever."""
    return [f"{e['cve']} {e['package']}: {e['note']}" for e in load()]
