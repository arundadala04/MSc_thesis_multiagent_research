"""Azure OpenAI access: the chat() and embed() calls the project needs."""
import time

import numpy as np
from openai import (APIConnectionError, APITimeoutError, AzureOpenAI,
                    InternalServerError, RateLimitError)

from devsecagent import config

RETRYABLE = (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError)


def client():
    config.check()
    return AzureOpenAI(
        azure_endpoint=config.AZURE_OPENAI_ENDPOINT,
        api_key=config.AZURE_OPENAI_API_KEY,
        api_version=config.AZURE_OPENAI_API_VERSION,
    )


def chat(prompt, system="You are a helpful assistant.", temperature=0.0):
    """Send a prompt to GPT-4o and return the reply text.

    Retries with a growing wait on rate limits and transient errors so a long
    evaluation run is not stopped by the Azure tokens-per-minute limit.
    """
    for attempt in range(6):
        try:
            response = client().chat.completions.create(
                model=config.CHAT_DEPLOYMENT,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content.strip()
        except RETRYABLE:
            if attempt == 5:
                raise
            time.sleep(2 ** attempt)


def embed(texts):
    """Return embeddings for the given texts as a float32 array, one row per text."""
    for attempt in range(6):
        try:
            response = client().embeddings.create(
                model=config.EMBEDDING_DEPLOYMENT,
                input=list(texts),
            )
            return np.array([row.embedding for row in response.data], dtype="float32")
        except RETRYABLE:
            if attempt == 5:
                raise
            time.sleep(2 ** attempt)
