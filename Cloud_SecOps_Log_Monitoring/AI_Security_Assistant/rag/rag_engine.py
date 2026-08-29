
"""
KIROTRACE - LOCAL RAG ENGINE
============================

Day 6:
    Local Knowledge Base + Retrieval Augmented Generation foundation.

Purpose:
    1. Load local cybersecurity Markdown knowledge.
    2. Load local KiroTrace JSON evidence through manifest.json.
    3. Split documents into retrieval chunks.
    4. Generate embeddings through local Ollama.
    5. Store a local JSON vector index.
    6. Retrieve relevant chunks using hybrid retrieval.

Retrieval strategy:
    - Exact identifier matching first:
        * IPv4 addresses
        * IPv6 addresses
        * Event IDs
        * Usernames
    - Semantic cosine similarity second.
    - Exact and semantic results are merged.
    - Duplicate chunks are removed.
    - Exact evidence is prioritized over generic knowledge.

Privacy / Architecture:
    - No ChatGPT API.
    - No Gemini API.
    - No external web search.
    - No cloud AI service.
    - Embeddings are generated locally by Ollama.
    - Source documents remain local.
    - KiroTrace project data is treated as read-only evidence.

Models:
    Embedding model: nomic-embed-text:latest
    Generation model: phi3:mini (used by generator.py)

Runtime:
    Python 3.14+
    Ollama running locally at http://localhost:11434
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any

import requests


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

KNOWLEDGE_BASE_DIR = BASE_DIR / "knowledge_base"
CYBERSECURITY_DIR = KNOWLEDGE_BASE_DIR / "cybersecurity"
PROJECT_DATA_DIR = KNOWLEDGE_BASE_DIR / "project_data"

MANIFEST_PATH = PROJECT_DATA_DIR / "manifest.json"

RAG_DIR = BASE_DIR / "rag"
INDEX_PATH = RAG_DIR / "index.json"


# ============================================================
# OLLAMA CONFIGURATION
# ============================================================

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_EMBED_ENDPOINT = f"{OLLAMA_BASE_URL}/api/embed"

EMBEDDING_MODEL = "nomic-embed-text:latest"

REQUEST_TIMEOUT_SECONDS = 120


# ============================================================
# RAG CONFIGURATION
# ============================================================

CHUNK_SIZE = 1200
CHUNK_OVERLAP = 200

DEFAULT_TOP_K = 5

MIN_RETRIEVAL_SCORE = 0.20

# Exact identifier matches receive a deterministic priority
# over semantic-only matches.
EXACT_MATCH_PRIORITY = 2.0

# Additional score contribution for each exact identifier type.
IP_MATCH_BONUS = 1.00
EVENT_ID_MATCH_BONUS = 1.00
USERNAME_MATCH_BONUS = 0.80

# Maximum semantic candidates examined before final ranking.
SEMANTIC_CANDIDATE_LIMIT = 50


# ============================================================
# IDENTIFIER REGEX
# ============================================================

# IPv4 candidates are validated with ipaddress rather than
# trusting regex alone.
IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])"
)

# Broad IPv6 candidate detection.
IPV6_PATTERN = re.compile(
    r"(?<![\w:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![\w:])"
)

# KiroTrace event IDs are generally hexadecimal identifiers.
# The length is intentionally broad enough to support existing
# and future event ID formats.
EVENT_ID_PATTERN = re.compile(
    r"\b(?:event[_\s-]?id|eventid)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9._:-]{8,128})[\"']?",
    re.IGNORECASE,
)

# Common username field patterns.
USERNAME_PATTERN = re.compile(
    r"\b(?:username|user|account|principal)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9._@\\-]+)",
    re.IGNORECASE,
)


# ============================================================
# HTTP SESSION
# ============================================================

SESSION = requests.Session()


# ============================================================
# GENERAL HELPERS
# ============================================================


def ensure_directories() -> None:
    """Ensure required RAG directories exist."""

    RAG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    CYBERSECURITY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    PROJECT_DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def normalize_text(text: str) -> str:
    """Normalize whitespace while preserving readable content."""

    lines: list[str] = []

    for line in text.splitlines():
        cleaned = " ".join(
            line.strip().split()
        )

        if cleaned:
            lines.append(cleaned)

    return "\n".join(lines)


def safe_relative_path(
    path: Path,
    base: Path,
) -> str:
    """Return a readable relative path."""

    try:
        return str(
            path.resolve().relative_to(
                base.resolve()
            )
        )

    except ValueError:
        return str(path)


# ============================================================
# IDENTIFIER EXTRACTION
# ============================================================


def extract_ip_addresses(
    text: str,
) -> set[str]:
    """
    Extract valid IPv4 and IPv6 addresses.

    Regex finds candidates.
    ipaddress validates them before returning.
    """

    addresses: set[str] = set()

    for match in IPV4_PATTERN.finditer(text):
        candidate = match.group(0)

        try:
            address = ipaddress.ip_address(
                candidate
            )

        except ValueError:
            continue

        addresses.add(
            str(address)
        )

    for match in IPV6_PATTERN.finditer(text):
        candidate = match.group(0)

        try:
            address = ipaddress.ip_address(
                candidate
            )

        except ValueError:
            continue

        addresses.add(
            str(address)
        )

    return addresses


def extract_event_ids(
    text: str,
) -> set[str]:
    """
    Extract event IDs from explicit event-ID fields.

    Supported examples:
        event_id: abc123...
        eventID: abc123...
        event-id = abc123...
        "event_id": "abc123..."

    Values are normalized to lowercase for matching.
    """
    return {
        match.group(1).strip().lower()
        for match in EVENT_ID_PATTERN.finditer(text)
        if match.group(1).strip()
    }


def extract_usernames(
    text: str,
) -> set[str]:
    """
    Extract usernames from common structured fields.

    Example:
        username: admin
        user=admin
        account: admin
    """

    usernames: set[str] = set()

    for match in USERNAME_PATTERN.finditer(text):
        username = match.group(1).strip()

        if username:
            usernames.add(
                username.lower()
            )

    return usernames


def extract_identifiers(
    text: str,
) -> dict[str, set[str]]:
    """Extract all supported security identifiers."""

    return {
        "ips": extract_ip_addresses(text),
        "event_ids": extract_event_ids(text),
        "usernames": extract_usernames(text),
    }


# ============================================================
# DOCUMENT LOADING
# ============================================================


def load_markdown_documents() -> list[dict[str, Any]]:
    """
    Load cybersecurity Markdown documents from the local
    knowledge base.
    """

    documents: list[dict[str, Any]] = []

    if not CYBERSECURITY_DIR.exists():
        return documents

    for path in sorted(
        CYBERSECURITY_DIR.glob("*.md")
    ):
        try:
            text = path.read_text(
                encoding="utf-8"
            )

        except UnicodeDecodeError:
            text = path.read_text(
                encoding="utf-8-sig"
            )

        text = normalize_text(text)

        if not text:
            continue

        documents.append(
            {
                "source": path.name,
                "source_path": str(
                    path.resolve()
                ),
                "source_type": "cybersecurity_knowledge",
                "format": "markdown",
                "read_only": True,
                "text": text,
            }
        )

    return documents


def resolve_manifest_source(
    source_path: str,
) -> Path:
    """
    Resolve a manifest path relative to the manifest directory.

    Relative paths keep the project portable.
    """

    return (
        MANIFEST_PATH.parent / source_path
    ).resolve()


def load_project_data_documents() -> list[dict[str, Any]]:
    """
    Load KiroTrace JSON sources defined in manifest.json.

    These files are treated as read-only evidence.
    """

    documents: list[dict[str, Any]] = []

    if not MANIFEST_PATH.exists():
        return documents

    try:
        manifest = json.loads(
            MANIFEST_PATH.read_text(
                encoding="utf-8-sig"
            )
        )

    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise RuntimeError(
            "Unable to read project-data manifest: "
            f"{MANIFEST_PATH}"
        ) from exc

    if not isinstance(
        manifest,
        dict,
    ):
        raise ValueError(
            "manifest.json root must be a JSON object."
        )

    sources = manifest.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        raise ValueError(
            "manifest.json 'sources' must be a list."
        )

    for source in sources:

        if not isinstance(
            source,
            dict,
        ):
            continue

        source_path = source.get(
            "path"
        )

        if not source_path:
            continue

        resolved_path = resolve_manifest_source(
            str(source_path)
        )

        if not resolved_path.exists():
            print(
                "[WARNING] Project source not found: "
                f"{resolved_path}"
            )
            continue

        try:
            raw_text = resolved_path.read_text(
                encoding="utf-8-sig"
            )

        except UnicodeDecodeError:
            raw_text = resolved_path.read_text(
                encoding="utf-8"
            )

        try:
            parsed_json = json.loads(
                raw_text
            )

            text = json.dumps(
                parsed_json,
                indent=2,
                ensure_ascii=False,
            )

        except json.JSONDecodeError:
            text = raw_text

        text = normalize_text(text)

        if not text:
            continue

        documents.append(
            {
                "source": source.get(
                    "name",
                    resolved_path.name,
                ),
                "source_path": str(
                    resolved_path
                ),
                "source_type": source.get(
                    "type",
                    "project_data",
                ),
                "format": "json",
                "read_only": bool(
                    source.get(
                        "read_only",
                        True,
                    )
                ),
                "text": text,
            }
        )

    return documents


def load_all_documents() -> list[dict[str, Any]]:
    """Load all local RAG sources."""

    documents: list[dict[str, Any]] = []

    documents.extend(
        load_markdown_documents()
    )

    documents.extend(
        load_project_data_documents()
    )

    return documents


# ============================================================
# DOCUMENT CHUNKING
# ============================================================

def split_text(
    text: str,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    """
    Split text into readable overlapping chunks without
    cutting through words or lines.

    The chunker prefers line boundaries and only falls back
    to a hard character split when a single line is larger
    than the configured chunk size.
    """

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be greater than zero."
        )

    if overlap < 0:
        raise ValueError(
            "overlap cannot be negative."
        )

    if overlap >= chunk_size:
        raise ValueError(
            "overlap must be smaller than chunk_size."
        )

    text = text.strip()

    if not text:
        return []

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    if not lines:
        return []

    chunks: list[str] = []
    current_lines: list[str] = []
    current_length = 0

    for line in lines:

        line_length = len(line)

        # ----------------------------------------------------
        # Normal case: line fits into current chunk.
        # ----------------------------------------------------

        if (
            current_lines
            and current_length + 1 + line_length
            > chunk_size
        ):
            chunks.append(
                "\n".join(current_lines).strip()
            )

            # Keep a small line-based overlap rather than
            # cutting the previous chunk at a character offset.
            overlap_lines: list[str] = []
            overlap_length = 0

            for previous_line in reversed(
                current_lines
            ):
                additional_length = (
                    len(previous_line)
                    + (
                        1
                        if overlap_lines
                        else 0
                    )
                )

                if (
                    overlap_length
                    + additional_length
                    > overlap
                ):
                    break

                overlap_lines.insert(
                    0,
                    previous_line,
                )

                overlap_length += (
                    additional_length
                )

            current_lines = overlap_lines
            current_length = sum(
                len(item)
                for item in current_lines
            )

            if current_lines:
                current_length += (
                    len(current_lines) - 1
                )

        # ----------------------------------------------------
        # Oversized single line.
        #
        # This is the only case where a hard split is needed.
        # Split at whitespace when possible.
        # ----------------------------------------------------

        if line_length > chunk_size:

            if current_lines:
                chunks.append(
                    "\n".join(current_lines).strip()
                )

                current_lines = []
                current_length = 0

            remaining = line

            while len(remaining) > chunk_size:

                split_at = remaining.rfind(
                    " ",
                    0,
                    chunk_size + 1,
                )

                if split_at <= 0:
                    split_at = chunk_size

                piece = remaining[
                    :split_at
                ].strip()

                if piece:
                    chunks.append(
                        piece
                    )

                remaining = remaining[
                    split_at:
                ].strip()

            if remaining:
                current_lines = [
                    remaining
                ]
                current_length = len(
                    remaining
                )

            continue

        # ----------------------------------------------------
        # Add normal line.
        # ----------------------------------------------------

        if current_lines:
            current_length += 1

        current_lines.append(
            line
        )

        current_length += line_length

    if current_lines:
        chunks.append(
            "\n".join(current_lines).strip()
        )

    return [
        chunk
        for chunk in chunks
        if chunk
    ]

def build_chunks(
    documents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert documents into retrieval chunks."""

    chunks: list[dict[str, Any]] = []

    for document in documents:

        text = document.get(
            "text",
            "",
        )

        document_chunks = split_text(
            text
        )

        for index, chunk_text in enumerate(
            document_chunks
        ):

            chunks.append(
                {
                    "chunk_id": (
                        f"{document['source_type']}:"
                        f"{document['source']}:"
                        f"{index + 1}"
                    ),
                    "source": document[
                        "source"
                    ],
                    "source_path": document[
                        "source_path"
                    ],
                    "source_type": document[
                        "source_type"
                    ],
                    "format": document[
                        "format"
                    ],
                    "read_only": document[
                        "read_only"
                    ],
                    "chunk_index": index,
                    "text": chunk_text,
                }
            )

    return chunks


# ============================================================
# OLLAMA EMBEDDINGS
# ============================================================


def check_ollama() -> None:
    """Verify that local Ollama is reachable."""

    try:
        response = SESSION.get(
            OLLAMA_BASE_URL,
            timeout=10,
        )

    except requests.RequestException as exc:
        raise RuntimeError(
            "Cannot connect to Ollama at "
            f"{OLLAMA_BASE_URL}. "
            "Make sure Ollama is running."
        ) from exc

    if response.status_code != 200:
        raise RuntimeError(
            "Ollama is reachable but returned HTTP "
            f"{response.status_code}."
        )


def check_embedding_model() -> None:
    """Verify that the local embedding model exists."""

    try:
        response = SESSION.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=10,
        )

    except requests.RequestException as exc:
        raise RuntimeError(
            "Unable to query local Ollama models."
        ) from exc

    if response.status_code != 200:
        raise RuntimeError(
            "Ollama model listing failed: "
            f"HTTP {response.status_code}"
        )

    try:
        data = response.json()

    except ValueError as exc:
        raise RuntimeError(
            "Ollama returned invalid model-list JSON."
        ) from exc

    models = data.get(
        "models",
        []
    )

    available_models = {
        model.get("name")
        for model in models
        if isinstance(
            model,
            dict,
        )
    }

    if EMBEDDING_MODEL not in available_models:
        raise RuntimeError(
            f"Required embedding model "
            f"'{EMBEDDING_MODEL}' was not found.\n"
            "Run:\n"
            f"    ollama pull {EMBEDDING_MODEL}"
        )


def embed_text(
    text: str,
) -> list[float]:
    """Generate a local embedding using Ollama."""

    if not text.strip():
        raise ValueError(
            "Cannot generate an embedding for empty text."
        )

    payload = {
        "model": EMBEDDING_MODEL,
        "input": text,
    }

    try:
        response = SESSION.post(
            OLLAMA_EMBED_ENDPOINT,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    except requests.RequestException as exc:
        raise RuntimeError(
            "Failed to communicate with Ollama "
            "embedding API."
        ) from exc

    if response.status_code != 200:
        raise RuntimeError(
            "Ollama embedding request failed: "
            f"HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )

    try:
        data = response.json()

    except ValueError as exc:
        raise RuntimeError(
            "Ollama returned invalid JSON."
        ) from exc

    embeddings = data.get(
        "embeddings"
    )

    if (
        not isinstance(
            embeddings,
            list,
        )
        or not embeddings
    ):
        raise RuntimeError(
            "Ollama response did not contain embeddings."
        )

    vector = embeddings[0]

    if (
        not isinstance(
            vector,
            list,
        )
        or not vector
    ):
        raise RuntimeError(
            "Ollama returned an invalid embedding vector."
        )

    try:
        return [
            float(value)
            for value in vector
        ]

    except (
        TypeError,
        ValueError,
    ) as exc:
        raise RuntimeError(
            "Ollama returned a non-numeric embedding."
        ) from exc


# ============================================================
# VECTOR MATH
# ============================================================


def cosine_similarity(
    vector_a: list[float],
    vector_b: list[float],
) -> float:
    """Calculate cosine similarity between two vectors."""

    if len(vector_a) != len(vector_b):
        raise ValueError(
            "Cannot compare vectors with different dimensions."
        )

    dot_product = 0.0
    magnitude_a = 0.0
    magnitude_b = 0.0

    for a, b in zip(
        vector_a,
        vector_b,
    ):
        dot_product += a * b
        magnitude_a += a * a
        magnitude_b += b * b

    if (
        magnitude_a == 0.0
        or magnitude_b == 0.0
    ):
        return 0.0

    return dot_product / (
        math.sqrt(magnitude_a)
        * math.sqrt(magnitude_b)
    )


# ============================================================
# EXACT MATCH ANALYSIS
# ============================================================


def identifier_match_details(
    query: str,
    text: str,
) -> dict[str, set[str]]:
    """
    Return identifiers present in both query and chunk text.

    Matching is case-insensitive for event IDs/usernames.
    IP addresses are normalized through ipaddress.
    """

    query_identifiers = extract_identifiers(
        query
    )

    text_identifiers = extract_identifiers(
        text
    )

    return {
        "ips": (
            query_identifiers["ips"]
            & text_identifiers["ips"]
        ),
        "event_ids": (
            query_identifiers["event_ids"]
            & text_identifiers["event_ids"]
        ),
        "usernames": (
            query_identifiers["usernames"]
            & text_identifiers["usernames"]
        ),
    }


def has_exact_identifier_match(
    details: dict[str, set[str]],
) -> bool:
    """Return True when at least one exact identifier matched."""

    return any(
        bool(values)
        for values in details.values()
    )


def calculate_exact_bonus(
    details: dict[str, set[str]],
) -> float:
    """
    Calculate deterministic ranking bonus for exact matches.

    More than one matching identifier increases the ranking,
    but the bonus is capped to avoid runaway scores.
    """

    bonus = 0.0

    if details["ips"]:
        bonus += IP_MATCH_BONUS

    if details["event_ids"]:
        bonus += EVENT_ID_MATCH_BONUS

    if details["usernames"]:
        bonus += USERNAME_MATCH_BONUS

    return min(
        bonus,
        EXACT_MATCH_PRIORITY,
    )


# ============================================================
# INDEX BUILDING
# ============================================================


def build_index(
    output_path: Path = INDEX_PATH,
) -> dict[str, Any]:
    """Build the complete local vector index."""

    ensure_directories()

    print("=" * 72)
    print(
        "KIROTRACE - LOCAL RAG INDEX BUILDER"
    )
    print("=" * 72)

    print(
        "\n[1/4] Checking local Ollama..."
    )

    check_ollama()
    check_embedding_model()

    print(
        "[OK] Ollama and embedding model are available."
    )

    print(
        "\n[2/4] Loading local knowledge "
        "and project evidence..."
    )

    documents = load_all_documents()

    if not documents:
        raise RuntimeError(
            "No RAG documents were found."
        )

    print(
        f"[OK] Documents loaded: "
        f"{len(documents)}"
    )

    for document in documents:
        print(
            f"  - {document['source']}"
            f" [{document['source_type']}]"
        )

    print(
        "\n[3/4] Creating retrieval chunks..."
    )

    chunks = build_chunks(
        documents
    )

    if not chunks:
        raise RuntimeError(
            "No chunks were created from the documents."
        )

    print(
        f"[OK] Chunks created: "
        f"{len(chunks)}"
    )

    print(
        "\n[4/4] Generating local embeddings..."
    )

    indexed_chunks: list[
        dict[str, Any]
    ] = []

    for number, chunk in enumerate(
        chunks,
        start=1,
    ):

        print(
            f"  Embedding "
            f"{number}/{len(chunks)}: "
            f"{chunk['source']} "
            f"(chunk "
            f"{chunk['chunk_index'] + 1})"
        )

        vector = embed_text(
            chunk["text"]
        )

        indexed_chunk = dict(
            chunk
        )

        indexed_chunk[
            "embedding"
        ] = vector

        indexed_chunks.append(
            indexed_chunk
        )

    if not indexed_chunks:
        raise RuntimeError(
            "No chunks were successfully embedded."
        )

    index = {
        "schema_version": "1.1",
        "index_type": (
            "local_json_hybrid_vector_index"
        ),
        "embedding_provider": "ollama_local",
        "embedding_model": EMBEDDING_MODEL,
        "embedding_dimensions": len(
            indexed_chunks[0][
                "embedding"
            ]
        ),
        "chunk_size": CHUNK_SIZE,
        "chunk_overlap": CHUNK_OVERLAP,
        "retrieval_strategy": (
            "exact_identifier_plus_cosine_similarity"
        ),
        "document_count": len(
            documents
        ),
        "chunk_count": len(
            indexed_chunks
        ),
        "sources": sorted(
            {
                chunk["source"]
                for chunk in indexed_chunks
            }
        ),
        "chunks": indexed_chunks,
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            index,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "\n" + "=" * 72
    )
    print(
        "RAG INDEX BUILD COMPLETE"
    )
    print("=" * 72)

    print(
        f"Documents       : "
        f"{len(documents)}"
    )

    print(
        f"Chunks          : "
        f"{len(indexed_chunks)}"
    )

    print(
        "Embedding dims  : "
        f"{index['embedding_dimensions']}"
    )

    print(
        f"Index           : "
        f"{output_path}"
    )

    print(
        "Retrieval       : "
        "Hybrid exact + semantic"
    )

    print("=" * 72)

    return index


# ============================================================
# INDEX LOADING
# ============================================================


def load_index(
    index_path: Path = INDEX_PATH,
) -> dict[str, Any]:
    """Load an existing local RAG index."""

    if not index_path.exists():
        raise FileNotFoundError(
            f"RAG index not found: "
            f"{index_path}"
        )

    try:
        index = json.loads(
            index_path.read_text(
                encoding="utf-8-sig"
            )
        )

    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise RuntimeError(
            f"Unable to load RAG index: "
            f"{index_path}"
        ) from exc

    if not isinstance(
        index,
        dict,
    ):
        raise ValueError(
            "RAG index root must be a JSON object."
        )

    chunks = index.get(
        "chunks"
    )

    if not isinstance(
        chunks,
        list,
    ):
        raise ValueError(
            "RAG index 'chunks' must be a list."
        )

    if not chunks:
        raise ValueError(
            "RAG index contains no chunks."
        )

    return index


# ============================================================
# RETRIEVAL RESULT HELPERS
# ============================================================


def _result_key(
    chunk: dict[str, Any],
) -> str:
    """
    Return a stable identifier for deduplication.
    """

    chunk_id = chunk.get(
        "chunk_id"
    )

    if chunk_id:
        return str(
            chunk_id
        )

    return (
        f"{chunk.get('source', '')}:"
        f"{chunk.get('chunk_index', '')}"
    )


def _build_result(
    chunk: dict[str, Any],
    semantic_score: float,
    exact_details: dict[str, set[str]],
) -> dict[str, Any]:
    """Build a normalized retrieval result."""

    exact_bonus = calculate_exact_bonus(
        exact_details
    )

    exact_match = has_exact_identifier_match(
        exact_details
    )

    # Final ranking score is an internal retrieval score.
    # It must never be interpreted as security confidence.
    final_score = semantic_score + exact_bonus

    matched_identifiers: dict[str, list[str]] = {
        "ips": sorted(
            exact_details["ips"]
        ),
        "event_ids": sorted(
            exact_details["event_ids"]
        ),
        "usernames": sorted(
            exact_details["usernames"]
        ),
    }

    return {
        "score": round(
            final_score,
            6,
        ),
        "semantic_score": round(
            semantic_score,
            6,
        ),
        "exact_match": exact_match,
        "exact_bonus": round(
            exact_bonus,
            6,
        ),
        "retrieval_method": (
         "exact"
         if semantic_score == 0.0
        else "semantic"
    ),
        "matched_identifiers": matched_identifiers,
        "chunk_id": chunk[
            "chunk_id"
        ],
        "source": chunk[
            "source"
        ],
        "source_path": chunk[
            "source_path"
        ],
        "source_type": chunk[
            "source_type"
        ],
        "format": chunk[
            "format"
        ],
        "read_only": chunk[
            "read_only"
        ],
        "chunk_index": chunk[
            "chunk_index"
        ],
        "text": chunk[
            "text"
        ],
    }

def _is_mixed_knowledge_query(
    query: str,
) -> bool:
    """
    Detect queries that combine:
    - a cybersecurity knowledge request, and
    - an exact project/security identifier.

    This keeps evidence-only identifier retrieval unchanged.
    """

    lowered = query.lower().strip()

    knowledge_terms = (
        "what is",
        "what are",
        "what does",
        "define",
        "definition of",
        "meaning of",
        "explain",
        "how does",
        "how do",
        "why does",
    )

    return any(
        term in lowered
        for term in knowledge_terms
    )

# ============================================================
# HYBRID RETRIEVAL
# ============================================================

def retrieve(
    query: str,
    top_k: int = DEFAULT_TOP_K,
    min_score: float = MIN_RETRIEVAL_SCORE,
    index_path: Path = INDEX_PATH,
) -> list[dict[str, Any]]:
    """
    Retrieve relevant local knowledge/evidence.

    Strategy:

       1. Detect exact security identifiers in query.
       2. Scan chunks for exact identifier matches.
       3. Preserve exact matches.
       4. Generate a semantic query embedding when needed.
       5. Rank semantic candidates.
       6. Prioritize project evidence over generic cybersecurity knowledge.
       7. Merge exact + semantic results.
       8. Remove duplicates.
       9. Return top_k results.

    Exact identifiers are especially important for queries such as:

        What evidence is available for 203.0.113.50?

    because semantic similarity alone may select a generic
    security document instead of every relevant event chunk.
    """

    query = query.strip()

    if not query:
        raise ValueError(
            "Retrieval query cannot be empty."
        )

    if top_k <= 0:
        raise ValueError(
            "top_k must be greater than zero."
        )

    if min_score < -1.0:
        raise ValueError(
            "min_score cannot be below -1.0."
        )

    index = load_index(
        index_path
    )

    chunks = index.get(
        "chunks",
        []
    )

    if not chunks:
        return []

    query_identifiers = extract_identifiers(
        query
    )

    has_query_identifiers = any(
        bool(values)
        for values in query_identifiers.values()
    )

    exact_results: list[
        dict[str, Any]
    ] = []

    semantic_candidates: list[
        tuple[
            float,
            dict[str, Any],
            dict[str, set[str]],
        ]
    ] = []

    # --------------------------------------------------------
    # EXACT IDENTIFIER PASS
    # --------------------------------------------------------

    for chunk in chunks:

        text = str(
            chunk.get(
                "text",
                ""
            )
        )

        if not text:
            continue

        exact_details = identifier_match_details(
            query,
            text
        )

        if has_exact_identifier_match(
            exact_details
        ):
            result = _build_result(
                chunk=chunk,
                semantic_score=0.0,
                exact_details=exact_details,
            )

            exact_results.append(
                result
            )

    # --------------------------------------------------------
    # SEMANTIC PASS
    # --------------------------------------------------------

    #
    # If the query contains an exact identifier and exact
    # matches were found, we still perform semantic retrieval
    # so related contextual evidence can be added.
    #
    # For a pure exact-match query, however, the exact pass
    # already gives deterministic evidence and we avoid the
    # extra Ollama embedding call when enough exact evidence
    # exists.
    #
    skip_semantic = (
    has_query_identifiers
    and len(exact_results) >= top_k
    and not _is_mixed_knowledge_query(query)
 )

    if not skip_semantic:

        query_vector = embed_text(
            query
        )

        for chunk in chunks:

            embedding = chunk.get(
                "embedding"
            )

            if not isinstance(
                embedding,
                list,
            ):
                continue

            try:
                semantic_score = cosine_similarity(
                    query_vector,
                    [
                        float(value)
                        for value in embedding
                    ],
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            if semantic_score < min_score:
                continue

            exact_details = {
                 "ips": set(),
               "event_ids": set(),
              "usernames": set(),
         }

            semantic_candidates.append(
                (
                    semantic_score,
                    chunk,
                    exact_details,
                )
            )

        semantic_candidates.sort(
            key=lambda item: item[0],
            reverse=True,
        )

        semantic_candidates = semantic_candidates[
            :SEMANTIC_CANDIDATE_LIMIT
        ]

    # --------------------------------------------------------
    # MERGE RESULTS
    # --------------------------------------------------------

    merged: dict[
        str,
        dict[str, Any],
    ] = {}

    for result in exact_results:

        key = _result_key(
            result
        )

        existing = merged.get(
            key
        )

        if (
            existing is None
            or result["score"]
            > existing["score"]
        ):
            merged[key] = result

    for (
        semantic_score,
        chunk,
        exact_details,
    ) in semantic_candidates:

        result = _build_result(
            chunk=chunk,
            semantic_score=semantic_score,
            exact_details=exact_details,
        )

        key = _result_key(
            result
        )

        existing = merged.get(
            key
        )

        if (
            existing is None
            or result["score"]
            > existing["score"]
        ):
            merged[key] = result
    # --------------------------------------------------------
    # FINAL RANKING
    # --------------------------------------------------------

    results = list(
        merged.values()
    )

    results.sort(
        key=lambda item: (
            item["exact_match"],
            item["score"],
            item["semantic_score"],
        ),
        reverse=True,
    )

    #
    # For identifier-driven queries, exact evidence remains
    # the priority.
    #
    # Exception:
    # If the question combines an exact identifier with a
    # knowledge request, preserve some semantic knowledge
    # results so that project evidence does not completely
    # displace the requested cybersecurity knowledge.
    #
    if has_query_identifiers:
        exact = [
            result
            for result in results
            if result["retrieval_method"] == "exact"
        ]

        semantic = [
            result
            for result in results
            if result["retrieval_method"] == "semantic"
        ]

        if _is_mixed_knowledge_query(query) and semantic:

            semantic_slots = max(
                1,
                top_k // 2,
            )

            exact_slots = max(
                0,
                top_k - semantic_slots,
            )

            results = (
                exact[:exact_slots]
                + semantic[:semantic_slots]
            )

        else:
            results = (
                exact
                + semantic
            )

    return results[:top_k]
# ============================================================
# RETRIEVAL PRESENTATION
# ============================================================


def format_retrieval_results(
    query: str,
    results: list[dict[str, Any]],
) -> str:
    """Create a readable retrieval report."""

    lines = [
        "=" * 72,
        "KIROTRACE - LOCAL RAG RETRIEVAL",
        "=" * 72,
        f"Query: {query}",
        f"Results: {len(results)}",
        "",
    ]

    if not results:
        lines.append(
            "No sufficiently relevant local evidence was found."
        )

        lines.append(
            "=" * 72
        )

        return "\n".join(
            lines
        )

    for number, result in enumerate(
        results,
        start=1,
    ):

        matched = result.get(
            "matched_identifiers",
            {},
        )

        matched_parts: list[str] = []

        if matched.get("ips"):
            matched_parts.append(
                "IP="
                + ", ".join(
                    matched["ips"]
                )
            )

        if matched.get("event_ids"):
            matched_parts.append(
                "EventID="
                + ", ".join(
                    matched["event_ids"]
                )
            )

        if matched.get("usernames"):
            matched_parts.append(
                "Username="
                + ", ".join(
                    matched["usernames"]
                )
            )

        lines.extend(
            [
                "-" * 72,
                f"RESULT #{number}",
                "-" * 72,
                f"Score           : {result['score']}",
                f"Semantic Score  : {result['semantic_score']}",
                f"Exact Match     : {result['exact_match']}",
                f"Exact Bonus     : {result['exact_bonus']}",
                f"Source          : {result['source']}",
                f"Source Type     : {result['source_type']}",
                f"Chunk           : {result['chunk_index'] + 1}",
                f"Read Only       : {result['read_only']}",
            ]
        )

        if matched_parts:
            lines.append(
                "Matched         : "
                + " | ".join(
                    matched_parts
                )
            )

        lines.extend(
            [
                "",
                result["text"],
                "",
            ]
        )

    lines.append(
        "=" * 72
    )

    lines.append(
        "NOTE: Retrieval scores are relevance-ranking "
        "metrics only, not security confidence or risk scores."
    )

    return "\n".join(
        lines
    )


# ============================================================
# CLI
# ============================================================


def main() -> None:
    """
    Command-line demonstration.

    Running this file directly:
        1. Builds the local RAG index.
        2. Executes an exact-IP retrieval test.
        3. Executes a semantic retrieval test.
    """

    index = build_index()

    print(
        "\nRunning exact-IP retrieval test..."
    )

    exact_query = (
        "What evidence is available for "
        "203.0.113.50?"
    )

    exact_results = retrieve(
        query=exact_query,
        top_k=10,
    )

    print(
        "\n"
        + format_retrieval_results(
            exact_query,
            exact_results,
        )
    )

    if exact_results:
        exact_matches = [
            result
            for result in exact_results
            if result["exact_match"]
        ]

        print(
            "\n[OK] Exact-IP retrieval returned "
            f"{len(exact_matches)} exact-match result(s)."
        )

    else:
        print(
            "\n[WARNING] No exact-IP evidence was returned."
        )

    print(
        "\nRunning semantic retrieval test..."
    )

    semantic_query = (
        "What are the indicators of an SSH "
        "brute-force attack and how should "
        "a defender investigate it?"
    )

    semantic_results = retrieve(
        query=semantic_query,
        top_k=5,
    )

    print(
        "\n"
        + format_retrieval_results(
            semantic_query,
            semantic_results,
        )
    )

    if semantic_results:
        print(
            "\n[OK] Local semantic RAG retrieval is working."
        )

    else:
        print(
            "\n[WARNING] No relevant semantic results "
            "were returned."
        )


if __name__ == "__main__":
    main()
