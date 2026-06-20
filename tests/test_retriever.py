"""Tests for the hybrid retriever."""
import pytest

from devsecagent import config, kb, retriever
from devsecagent.retriever import rrf


def test_rrf_prefers_item_ranked_high_in_both():
    dense = [2, 0, 1]
    sparse = [2, 1, 0]
    scores = rrf([dense, sparse])
    assert max(scores, key=scores.get) == 2


def test_kb_loads():
    docs = kb.documents()
    assert len(docs) > 5
    assert any("PyYAML" in d for d in docs)


@pytest.mark.skipif(not config.AZURE_OPENAI_API_KEY, reason="Azure not configured")
def test_retriever_finds_relevant_note():
    r = retriever.Retriever(kb.documents())
    results = r.search("CVE-2020-14343 PyYAML code execution", k=3)
    assert any("PyYAML" in doc for doc in results)
