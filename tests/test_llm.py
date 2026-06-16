"""Connection test: proves the Azure GPT-4o deployment is reachable.

This makes a real API call, so it needs a filled-in .env. If the Azure key is
missing the test is skipped (so the suite still runs on a fresh checkout).
"""
import pytest

from devsecagent import config, llm


@pytest.mark.skipif(not config.AZURE_OPENAI_API_KEY,
                    reason="Azure settings not configured in .env")
def test_gpt4o_replies():
    answer = llm.chat("Reply with exactly the word: OK")
    assert "OK" in answer.upper()
