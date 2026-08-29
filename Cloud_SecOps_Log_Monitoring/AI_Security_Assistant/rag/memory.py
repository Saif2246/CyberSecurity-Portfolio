"""
KIROTRACE - LOCAL VECTOR MEMORY
================================

Persistent local long-term conversation memory.

Uses:
    - Ollama
    - nomic-embed-text
    - Local JSON storage
    - Cosine similarity

Security boundary:
    Long-term memory is contextual conversation history only.
    It is NOT project security evidence.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

import requests


# ============================================================
# CONFIGURATION
# ============================================================

OLLAMA_BASE_URL = "http://localhost:11434"

EMBED_ENDPOINT = f"{OLLAMA_BASE_URL}/api/embed"
LEGACY_EMBED_ENDPOINT = f"{OLLAMA_BASE_URL}/api/embeddings"

EMBEDDING_MODEL = "nomic-embed-text:latest"

MEMORY_FILE = Path(__file__).resolve().parent / "memory_store.json"

MAX_MEMORY_ITEMS = 100
DEFAULT_TOP_K = 3
MEMORY_SIMILARITY_THRESHOLD = 0.45

EMBEDDING_TIMEOUT_SECONDS = 30

MAX_QUESTION_CHARS = 2000
MAX_ANSWER_CHARS = 6000


# ============================================================
# TEXT VALIDATION
# ============================================================

def _clean_text(
    value: Any,
    max_chars: int,
) -> str:
    """Normalize and limit text."""

    if not isinstance(value, str):
        return ""

    value = value.strip()

    if not value:
        return ""

    return value[:max_chars]


def _valid_embedding(
    embedding: Any,
) -> bool:
    """Check whether embedding is a valid numeric vector."""

    if not isinstance(embedding, list):
        return False

    if not embedding:
        return False

    return all(
        isinstance(value, (int, float))
        and math.isfinite(float(value))
        for value in embedding
    )


# ============================================================
# MEMORY STORAGE
# ============================================================

def _load_memory() -> list[dict[str, Any]]:
    """
    Load persistent memory.

    Missing/corrupt memory does not crash the assistant.
    """

    if not MEMORY_FILE.exists():
        return []

    try:
        raw = MEMORY_FILE.read_text(
            encoding="utf-8"
        )

        data = json.loads(raw)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []

    if not isinstance(data, list):
        return []

    valid_records: list[dict[str, Any]] = []

    for item in data:

        if not isinstance(item, dict):
            continue

        question = _clean_text(
            item.get("question"),
            MAX_QUESTION_CHARS,
        )

        answer = _clean_text(
            item.get("answer"),
            MAX_ANSWER_CHARS,
        )

        embedding = item.get("embedding")

        if not question:
            continue

        if not answer:
            continue

        if not _valid_embedding(embedding):
            continue

        valid_records.append(
            {
                "question": question,
                "answer": answer,
                "timestamp": item.get(
                    "timestamp",
                    0,
                ),
                "embedding": [
                    float(value)
                    for value in embedding
                ],
            }
        )

    return valid_records


def _save_memory(
    records: list[dict[str, Any]],
) -> None:
    """Save memory atomically."""

    MEMORY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    bounded_records = records[
        -MAX_MEMORY_ITEMS:
    ]

    payload = json.dumps(
        bounded_records,
        ensure_ascii=False,
        indent=2,
    )

    temporary_file = MEMORY_FILE.with_suffix(
        ".tmp"
    )

    temporary_file.write_text(
        payload,
        encoding="utf-8",
    )

    temporary_file.replace(
        MEMORY_FILE
    )


# ============================================================
# OLLAMA EMBEDDING
# ============================================================

def _request_embedding(
    text: str,
) -> list[float]:
    """
    Generate an embedding using local Ollama.

    Current /api/embed endpoint is preferred.
    Legacy endpoint is supported as fallback.
    """

    text = _clean_text(
        text,
        MAX_QUESTION_CHARS,
    )

    if not text:
        raise ValueError(
            "Cannot embed empty text."
        )

    # --------------------------------------------------------
    # Current Ollama embedding API
    # --------------------------------------------------------

    try:

        response = requests.post(
            EMBED_ENDPOINT,
            json={
                "model": EMBEDDING_MODEL,
                "input": text,
            },
            timeout=EMBEDDING_TIMEOUT_SECONDS,
        )

        response.raise_for_status()

        data = response.json()

        embeddings = data.get(
            "embeddings"
        )

        if (
            isinstance(embeddings, list)
            and embeddings
            and _valid_embedding(
                embeddings[0]
            )
        ):
            return [
                float(value)
                for value in embeddings[0]
            ]

    except (
        requests.RequestException,
        ValueError,
        json.JSONDecodeError,
    ):
        pass

    # --------------------------------------------------------
    # Legacy Ollama embedding API
    # --------------------------------------------------------

    response = requests.post(
        LEGACY_EMBED_ENDPOINT,
        json={
            "model": EMBEDDING_MODEL,
            "prompt": text,
        },
        timeout=EMBEDDING_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()

    embedding = data.get(
        "embedding"
    )

    if not _valid_embedding(
        embedding
    ):
        raise RuntimeError(
            "Ollama returned an invalid embedding."
        )

    return [
        float(value)
        for value in embedding
    ]


# ============================================================
# COSINE SIMILARITY
# ============================================================

def _cosine_similarity(
    vector_a: list[float],
    vector_b: list[float],
) -> float:
    """Calculate cosine similarity."""

    if not vector_a or not vector_b:
        return 0.0

    if len(vector_a) != len(vector_b):
        return 0.0

    dot_product = sum(
        a * b
        for a, b in zip(
            vector_a,
            vector_b,
        )
    )

    magnitude_a = math.sqrt(
        sum(
            value * value
            for value in vector_a
        )
    )

    magnitude_b = math.sqrt(
        sum(
            value * value
            for value in vector_b
        )
    )

    if magnitude_a == 0.0:
        return 0.0

    if magnitude_b == 0.0:
        return 0.0

    return (
        dot_product
        / (magnitude_a * magnitude_b)
    )


# ============================================================
# STORE MEMORY
# ============================================================

def store_memory(
    question: str,
    answer: str,
) -> bool:
    """
    Store a successful conversation.

    Memory failures never break the security assistant.
    """

    question = _clean_text(
        question,
        MAX_QUESTION_CHARS,
    )

    answer = _clean_text(
        answer,
        MAX_ANSWER_CHARS,
    )

    if not question or not answer:
        return False

    try:

        memory_text = (
            f"User Question: {question}\n"
            f"Assistant Answer: {answer}"
        )

        embedding = _request_embedding(
            memory_text
        )

        records = _load_memory()

        # ----------------------------------------------------
        # Update exact duplicate
        # ----------------------------------------------------

        for record in records:

            if (
                record.get("question", "").casefold()
                == question.casefold()
            ):
                record["answer"] = answer
                record["timestamp"] = time.time()
                record["embedding"] = embedding

                _save_memory(records)

                return True

        # ----------------------------------------------------
        # Add new memory
        # ----------------------------------------------------

        records.append(
            {
                "question": question,
                "answer": answer,
                "timestamp": time.time(),
                "embedding": embedding,
            }
        )

        _save_memory(records)

        return True

    except (
        OSError,
        requests.RequestException,
        RuntimeError,
        ValueError,
    ):
        return False


# ============================================================
# RETRIEVE MEMORY
# ============================================================

def retrieve_memories(
    question: str,
    top_k: int = DEFAULT_TOP_K,
) -> list[dict[str, Any]]:
    """
    Retrieve semantically relevant previous conversations.

    Similarity is retrieval relevance only.
    It is NOT security confidence or risk.
    """

    question = _clean_text(
        question,
        MAX_QUESTION_CHARS,
    )

    if not question:
        return []

    if top_k <= 0:
        return []

    records = _load_memory()

    if not records:
        return []

    try:

        query_embedding = _request_embedding(
            question
        )

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
    ):
        return []

    scored_records: list[
        dict[str, Any]
    ] = []

    for record in records:

        embedding = record.get(
            "embedding"
        )

        if not _valid_embedding(
            embedding
        ):
            continue

        similarity = _cosine_similarity(
            query_embedding,
            embedding,
        )

        if (
            similarity
            < MEMORY_SIMILARITY_THRESHOLD
        ):
            continue

        scored_records.append(
            {
                "question": record.get(
                    "question",
                    "",
                ),
                "answer": record.get(
                    "answer",
                    "",
                ),
                "similarity": round(
                    similarity,
                    4,
                ),
            }
        )

    scored_records.sort(
        key=lambda item: item[
            "similarity"
        ],
        reverse=True,
    )

    return scored_records[
        :top_k
    ]


# ============================================================
# BUILD MEMORY CONTEXT
# ============================================================

def build_memory_context(
    memories: list[dict[str, Any]],
) -> str:
    """
    Convert retrieved memories into clearly labelled
    contextual information.

    This is NOT project evidence.
    """

    if (
        not isinstance(
            memories,
            list,
        )
        or not memories
    ):
        return (
            "No relevant long-term conversation memory."
        )

    sections: list[str] = []

    for index, memory in enumerate(
        memories,
        start=1,
    ):

        if not isinstance(
            memory,
            dict,
        ):
            continue

        question = _clean_text(
            memory.get("question"),
            MAX_QUESTION_CHARS,
        )

        answer = _clean_text(
            memory.get("answer"),
            MAX_ANSWER_CHARS,
        )

        if not question or not answer:
            continue

        sections.append(
            f"Memory {index}\n"
            f"Previous User Question: {question}\n"
            f"Previous Assistant Answer: {answer}"
        )

    if not sections:
        return (
            "No relevant long-term conversation memory."
        )

    return "\n\n".join(
        sections
    )


# ============================================================
# SELF TEST
# ============================================================

def run_self_test() -> bool:
    """Run deterministic memory tests."""

    vector_a = [
        1.0,
        0.0,
        0.0,
    ]

    vector_b = [
        1.0,
        0.0,
        0.0,
    ]

    vector_c = [
        0.0,
        1.0,
        0.0,
    ]

    identical_similarity = _cosine_similarity(
        vector_a,
        vector_b,
    )

    if abs(
        identical_similarity - 1.0
    ) > 0.0001:

        print(
            "[FAIL] Identical vector similarity."
        )

        return False

    orthogonal_similarity = _cosine_similarity(
        vector_a,
        vector_c,
    )

    if abs(
        orthogonal_similarity
    ) > 0.0001:

        print(
            "[FAIL] Orthogonal vector similarity."
        )

        return False

    context = build_memory_context(
        [
            {
                "question": (
                    "What happened with SSH?"
                ),
                "answer": (
                    "Previous analysis discussed "
                    "failed SSH attempts."
                ),
                "similarity": 0.91,
            }
        ]
    )

    if (
        "Previous User Question"
        not in context
    ):

        print(
            "[FAIL] Memory question formatting."
        )

        return False

    if (
        "Previous Assistant Answer"
        not in context
    ):

        print(
            "[FAIL] Memory answer formatting."
        )

        return False

    print(
        "[OK] Vector memory self-test passed."
    )

    return True


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if not run_self_test():
        raise SystemExit(1)