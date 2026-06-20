"""Hybrid retriever: dense (FAISS over embeddings) plus sparse (BM25), fused with RRF.

Given a CVE query it returns the most relevant notes from the knowledge base, which
the patcher uses as grounding for the fix.
"""
import faiss
import numpy as np
from rank_bm25 import BM25Okapi

from devsecagent import llm


def _tokens(text):
    return text.lower().split()


def rrf(rankings, k=60):
    """Reciprocal Rank Fusion: merge several best-first rankings into one score per item."""
    scores = {}
    for ranking in rankings:
        for position, item in enumerate(ranking):
            scores[item] = scores.get(item, 0.0) + 1.0 / (k + position + 1)
    return scores


class Retriever:
    def __init__(self, docs):
        self.docs = docs
        self.bm25 = BM25Okapi([_tokens(d) for d in docs])
        vectors = llm.embed(docs)
        faiss.normalize_L2(vectors)
        self.index = faiss.IndexFlatIP(vectors.shape[1])
        self.index.add(vectors)

    def search(self, query, k=3):
        fused = rrf([self._dense_rank(query), self._sparse_rank(query)])
        best = sorted(fused, key=fused.get, reverse=True)[:k]
        return [self.docs[i] for i in best]

    def _dense_rank(self, query):
        q = llm.embed([query])
        faiss.normalize_L2(q)
        _, idx = self.index.search(q, len(self.docs))
        return [int(i) for i in idx[0]]

    def _sparse_rank(self, query):
        scores = self.bm25.get_scores(_tokens(query))
        return [int(i) for i in np.argsort(scores)[::-1]]
