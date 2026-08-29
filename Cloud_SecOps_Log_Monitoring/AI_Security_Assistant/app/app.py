from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from uuid import uuid4
import streamlit as st
from audit.audit_logger import log_audit_event

# ============================================================
# PAGE CONFIGURATION
# Must be the first Streamlit command.
# ============================================================

st.set_page_config(
    page_title="KiroTrace AI Security Assistant",
    page_icon="K",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROJECT PATH
# ============================================================

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# RAG BACKEND
# ============================================================

try:
    from rag.generator import generate_security_answer

    RAG_IMPORT_OK = True
    RAG_IMPORT_ERROR = ""

except Exception as error:
    generate_security_answer = None
    RAG_IMPORT_OK = False
    RAG_IMPORT_ERROR = str(error)
try:
    from rag.memory import store_memory
except ImportError:
    store_memory = None
# ============================================================
# CUSTOM CSS
# Clean, lightweight UI styling.
# ============================================================

st.markdown(
    """
    <style>

    .stApp {
        background: #f6f8fb;
    }

    .block-container {
        max-width: 1380px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    [data-testid="stDecoration"] {
        display: none;
    }

    .app-header {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 14px;
        padding: 1.45rem 1.55rem;
        margin-bottom: 1.35rem;
    }

    .app-header-title {
        color: #f8fafc;
        font-size: 1.9rem;
        font-weight: 800;
        letter-spacing: -0.035em;
        line-height: 1.2;
    }

    .app-header-subtitle {
        color: #aeb9c8;
        font-size: 0.88rem;
        line-height: 1.55;
        margin-top: 0.45rem;
        max-width: 850px;
    }

    .app-header-badge {
        display: inline-block;
        margin-top: 0.85rem;
        padding: 0.28rem 0.6rem;
        border-radius: 999px;
        background: #172554;
        border: 1px solid #1d4ed8;
        color: #93c5fd;
        font-size: 0.64rem;
        font-weight: 800;
        letter-spacing: 0.07em;
    }

    .section-title {
        color: #111827;
        font-size: 1.15rem;
        font-weight: 800;
        letter-spacing: -0.015em;
        margin-top: 0.3rem;
    }

    .section-description {
        color: #64748b;
        font-size: 0.82rem;
        line-height: 1.5;
        margin-top: 0.18rem;
        margin-bottom: 0.8rem;
    }

    .question-header {
        background: #ffffff;
        border: 1px solid #dbe3ec;
        border-radius: 12px;
        padding: 1rem 1.1rem 0.25rem 1.1rem;
        margin-bottom: 0.8rem;
    }

    .question-label {
        color: #334155;
        font-size: 0.72rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.25rem;
    }

    .status-card {
        background: #ffffff;
        border: 1px solid #dbe3ec;
        border-radius: 10px;
        padding: 0.85rem 0.95rem;
        min-height: 82px;
    }

    .status-label {
        color: #64748b;
        font-size: 0.66rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.35rem;
    }

    .status-value {
        color: #0f172a;
        font-size: 0.86rem;
        font-weight: 750;
    }

    .status-ok {
        color: #047857;
    }

    .status-warning {
        color: #b45309;
    }

    .status-neutral {
        color: #475569;
    }

    .answer-header {
        color: #0f172a;
        font-size: 0.72rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.55rem;
    }
    .sidebar-brand {
    margin-bottom: 1.4rem;
}

.sidebar-brand-title {
    color: #111827;
    font-size: 1.35rem;
    font-weight: 800;
}

.sidebar-brand-subtitle {
    color: #64748b;
    font-size: 0.72rem;
    margin-top: 0.2rem;
}

.sidebar-section {
    color: #64748b;
    font-size: 0.68rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin: 1.15rem 0 0.55rem;
}

.pipeline-item {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    margin-bottom: 0.55rem;
}

.pipeline-number {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: #e2e8f0;
    color: #334155;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.68rem;
    font-weight: 800;
}

.pipeline-text {
    color: #475569;
    font-size: 0.76rem;
}

.answer-container {
    background: #ffffff;
    border: 1px solid #dbe3ec;
    border-radius: 12px;
    padding: 1.1rem 1.2rem;
    margin-top: 0.4rem;
}
/* Hide Streamlit heading anchor icons inside AI answer */

.st-key-answer_container h1 a,
.st-key-answer_container h2 a,
.st-key-answer_container h3 a,
.st-key-answer_container h4 a {
    display: none !important;
}

.st-key-answer_container h1 button,
.st-key-answer_container h2 button,
.st-key-answer_container h3 button,
.st-key-answer_container h4 button {
    display: none !important;
}
.answer-container,
.answer-container p,
.answer-container li,
.answer-container ul,
.answer-container ol,
.answer-container h1,
.answer-container h2,
.answer-container h3,
.answer-container h4,
.answer-container strong,
.answer-container em,
.answer-container code {
    color: #0f172a !important;
}

.answer-container a {
    color: #1d4ed8 !important;
}

.answer-container blockquote {
    color: #334155 !important;
    border-left: 3px solid #cbd5e1;
    padding-left: 0.8rem;
}
[data-testid="stVerticalBlock"]:has(.answer-header) {
    background: #ffffff;
    border: 1px solid #dbe3ec;
    border-radius: 12px;
    padding: 1.1rem 1.2rem;
    margin-top: 0.4rem;
}

[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"],
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] p,
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] li,
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] h1,
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] h2,
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] h3,
[data-testid="stVerticalBlock"]:has(.answer-header) [data-testid="stMarkdownContainer"] strong {
    color: #0f172a !important;
}
.footer {
    color: #94a3b8;
    font-size: 0.7rem;
    text-align: center;
    padding: 2rem 0 0.5rem;
}
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "question" not in st.session_state:
    st.session_state["question"] = ""

if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None

if "has_analyzed" not in st.session_state:
    st.session_state["has_analyzed"] = False

MAX_CONVERSATION_HISTORY = 10

if "conversation_history" not in st.session_state:
    st.session_state["conversation_history"] = []

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def set_question(question: str) -> None:
    """Store an example security question."""
    st.session_state["question"] = question


def clear_analysis() -> None:
    """Clear the current analysis."""
    st.session_state["analysis_result"] = None
    st.session_state["has_analyzed"] = False

def clear_conversation() -> None:
    """Clear the current analysis and conversation memory."""
    st.session_state["question"] = ""
    st.session_state["analysis_result"] = None
    st.session_state["has_analyzed"] = False
    st.session_state["conversation_history"] = []
def render_sources(sources: list[Any]) -> None:
    """Render retrieved RAG evidence sources."""

    if not isinstance(sources, list) or not sources:
        st.info("No retrieved evidence sources were returned.")
        return

    valid_sources = [
        source
        for source in sources
        if isinstance(source, dict)
    ]

    if not valid_sources:
        st.info("No valid evidence sources were returned.")
        return

    for index, source in enumerate(
        valid_sources,
        start=1,
    ):

        source_name = source.get(
            "source",
            "Unknown source",
        )

        source_type = source.get(
            "source_type",
            "Unknown type",
        )

        chunk_id = source.get(
            "chunk_id",
            "N/A",
        )

        chunk_index = source.get(
            "chunk_index",
            "N/A",
        )

        exact_match = bool(
            source.get(
                "exact_match",
                False,
            )
        )

        matched_identifiers = source.get(
            "matched_identifiers",
            {},
        )

        with st.expander(
            f"Evidence {index} · {source_name}",
            expanded=(index == 1),
        ):

            left, right = st.columns(2)

            with left:

                st.markdown(
                    '<div class="status-label">Source Type</div>',
                    unsafe_allow_html=True,
                )

                st.write(source_type)

                st.markdown(
                    '<div class="status-label">Chunk ID</div>',
                    unsafe_allow_html=True,
                )

                st.code(
                    str(chunk_id),
                    language="text",
                )

            with right:

                st.markdown(
                    '<div class="status-label">Chunk Index</div>',
                    unsafe_allow_html=True,
                )

                st.write(chunk_index)

                st.markdown(
                    '<div class="status-label">Match Type</div>',
                    unsafe_allow_html=True,
                )

                if exact_match:
                    st.success("Exact identifier match")
                else:
                    st.write("Semantic / contextual match")

            # ------------------------------------------------
            # MATCHED IDENTIFIERS
            # ------------------------------------------------

            if isinstance(
                matched_identifiers,
                dict,
            ):

                identifier_items = []

                for identifier_type, values in matched_identifiers.items():

                    if not isinstance(values, list):
                        continue

                    cleaned_values = [
                        str(value).strip()
                        for value in values
                        if str(value).strip()
                    ]

                    if cleaned_values:
                        identifier_items.append(
                            (
                                str(identifier_type),
                                cleaned_values,
                            )
                        )

                if identifier_items:

                    st.markdown(
                        '<div class="status-label">'
                        'Matched Identifiers'
                        '</div>',
                        unsafe_allow_html=True,
                    )

                    for identifier_type, values in identifier_items:

                        label = identifier_type.replace(
                            "_",
                            " ",
                        ).title()

                        st.markdown(
                            f"**{label}**"
                        )

                        for value in values:
                            st.code(
                                value,
                                language="text",
                            )

def render_metadata(
    result: dict[str, Any],
) -> None:
    """Render compact backend metadata."""

    metadata = {
        "question": result.get(
            "question"
        ),
        "retrieved_count": result.get(
            "retrieved_count",
            0,
        ),
        "used_llm": result.get(
            "used_llm",
            False,
        ),
        "fallback": result.get(
            "fallback",
            False,
        ),
        "generation_error": result.get(
            "generation_error",
            "",
        ),
    }

    with st.expander(
        "Backend Result Metadata"
    ):
        st.json(metadata)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">
                KiroTrace
            </div>
            <div class="sidebar-brand-subtitle">
                AI Security Assistant · v1.0
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="sidebar-section">System</div>',
        unsafe_allow_html=True,
    )

    if RAG_IMPORT_OK:

        st.success(
            "RAG backend available"
        )

    else:

        st.error(
            "RAG backend unavailable"
        )

        if RAG_IMPORT_ERROR:

            with st.expander(
                "Backend error"
            ):

                st.code(
                    RAG_IMPORT_ERROR,
                    language="text",
                )

    st.markdown(
        '<div class="sidebar-section">Analysis Pipeline</div>',
        unsafe_allow_html=True,
    )

    pipeline_items = [
        "Security question",
        "Local RAG retrieval",
        "Evidence-grounded generation",
        "Security response",
        "Evidence attribution",
    ]

    for index, item in enumerate(
        pipeline_items,
        start=1,
    ):

        st.markdown(
    f"""<div class="pipeline-item">
 <div class="pipeline-number">{index}</div>
 <div class="pipeline-text">{item}</div>
 </div>""",
    unsafe_allow_html=True,
 )
    st.markdown(
        '<div class="sidebar-section">Example Questions</div>',
        unsafe_allow_html=True,
    )

    example_questions = [
        (
            "SSH brute force",
            "What does the KiroTrace evidence show "
            "about the SSH brute force activity?",
        ),
        (
            "Compromise assessment",
            "Was the SSH activity enough to "
            "confirm account compromise?",
        ),
        (
            "Evidence review",
            "What evidence supports the "
            "suspicious SSH activity?",
        ),
        (
            "Investigation",
            "What should an analyst investigate next?",
        ),
    ]

    for index, (
        label,
        example,
    ) in enumerate(
        example_questions
    ):

        if st.button(
            label,
            key=f"example_{index}",
            use_container_width=True,
        ):

            set_question(
                example
            )

            st.rerun()

    st.markdown(
        '<div class="sidebar-section">Controls</div>',
        unsafe_allow_html=True,
    )

    if st.button(
        "Clear Analysis",
        use_container_width=True,
    ):

        clear_analysis()
        st.rerun()

    if st.button(
       "Clear Conversation",
         use_container_width=True,
  ):

     clear_conversation()
     st.rerun()
    st.caption(
        "Local RAG + KiroTrace telemetry + "
        "evidence-grounded LLM"
    )


# ============================================================
# MAIN HEADER
# ============================================================
st.html(
    """
    <div class="app-header">
        <div class="app-header-title">
            KiroTrace AI Security Assistant
        </div>

        <div class="app-header-subtitle">
            Evidence-grounded security analysis over
            KiroTrace telemetry and a local cybersecurity
            knowledge base.
        </div>

        <div class="app-header-badge">
            OFFLINE-FIRST · LOCAL RAG · SECURITY EVIDENCE
        </div>
    </div>
    """
)


# ============================================================
# INVESTIGATION SECTION
# ============================================================

st.markdown(
    '<div class="section-title">Security Investigation</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="section-description">'
    'Ask a security question and inspect the evidence '
    'used to produce the response.'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# QUESTION INPUT
# ============================================================

st.markdown(
    """
    <div class="question-header">
        <div class="question-label">
            Security Question
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
with st.form("security_analysis_form"):

    question = st.text_area(
        "Security Question",
        key="question",
        label_visibility="collapsed",
        placeholder=(
            "Example: What does the KiroTrace evidence show "
            "about the SSH brute force activity?"
        ),
        height=110,
    )

    analyze = st.form_submit_button(
        "Analyze Security Evidence",
        type="primary",
        use_container_width=True,
    )


# ============================================================
# ANALYSIS EXECUTION
# ============================================================

if analyze:
    request_id = str(uuid4())
    cleaned_question = question.strip()

    if not cleaned_question:

        st.error(
            "Enter a security question before running "
            "the analysis."
        )

        st.stop()

    if not RAG_IMPORT_OK:

        st.error(
            "The RAG backend could not be loaded. "
            "Fix the backend import before running "
            "an analysis."
        )

        st.stop()

    with st.spinner(
        "Retrieving local evidence and generating analysis..."
    ):
        try:
            conversation_history = st.session_state.get(
                "conversation_history",
                [],
            )

            if not isinstance(
                conversation_history,
                list,
            ):
                conversation_history = []

            conversation_history = conversation_history[
                -MAX_CONVERSATION_HISTORY:
            ]
            
            
            

            result = generate_security_answer(
                question=cleaned_question,
                conversation_history=conversation_history,
                request_id=request_id,
            )    
            if isinstance(result, dict):
                retrieved_count = result.get(
                    "retrieved_count",
                    0,
                )

                used_llm = bool(
                    result.get(
                        "used_llm",
                        False,
                    )
                )

                fallback = bool(
                    result.get(
                        "fallback",
                        False,
                    )
                )

                generation_error = str(
                    result.get(
                        "generation_error",
                        "",
                    )
                    or ""
                )

                if fallback:
                    response_mode = "DETERMINISTIC_FALLBACK"
                elif used_llm:
                    response_mode = "LLM_GENERATED"
                else:
                    response_mode = "NON_LLM"

                # ------------------------------------------------
                # AUDIT STATUS
                # ------------------------------------------------

                tool_status = str(
                    result.get(
                        "tool_status",
                        "",
                    )
                    or ""
                ).upper()

                tool_execution = bool(
                    result.get(
                        "tool_execution",
                        False,
                    )
                )

                if tool_status == "DENIED":
                    audit_success = False
                    audit_status = "DENIED"
                    audit_reason = str(
                        result.get(
                            "tool_reason",
                            "Request was denied by security controls.",
                        )
                        or "Request was denied by security controls."
                    )

                elif tool_execution and tool_status not in {
                    "",
                    "SUCCESS",
                    "EXECUTED",
                }:
                    audit_success = False
                    audit_status = "FAILED"
                    audit_reason = (
                        f"Tool execution failed; "
                        f"tool_status={tool_status}; "
                        f"response_mode={response_mode}"
                    )

                    if generation_error:
                        audit_reason += (
                            f"; generation_error={generation_error}"
                        )

                else:
                    audit_success = not bool(
                        generation_error
                    )

                    audit_status = (
                        "COMPLETED"
                        if audit_success
                        else "COMPLETED_WITH_GENERATION_ERROR"
                    )

                    audit_reason = (
                        f"RAG investigation completed; "
                        f"retrieved_count={retrieved_count}; "
                        f"response_mode={response_mode}; "
                        f"fallback={fallback}"
                    )

                    if generation_error:
                        audit_reason += (
                            f"; generation_error={generation_error}"
                        )

                if generation_error:
                    audit_reason += (
                        f"; generation_error={generation_error}"
                    )

                log_audit_event(
                    event_type="AI_SECURITY_INVESTIGATION",
                    success=audit_success,
                    status=audit_status,
                    request_id=request_id,
                    question=cleaned_question,
                    policy_category="AI_SECURITY_ANALYSIS",
                    execution_mode="rag",
                    reason=audit_reason,
                    error=generation_error,
                    audit_file=(
                        PROJECT_ROOT
                        / "audit"
                        / "audit.log.jsonl"
                    ),
                )

        except Exception as error:
            log_audit_event(
                event_type="AI_SECURITY_INVESTIGATION",
                success=False,
                status="FAILED",
                request_id=request_id,
                question=cleaned_question,
                policy_category="AI_SECURITY_ANALYSIS",
                execution_mode="rag",
                reason="Security analysis execution failed.",
                error=str(error),
                audit_file=(
                    PROJECT_ROOT
                    / "audit"
                    / "audit.log.jsonl"
                ),
            )

            st.error(
                "The security analysis failed."
            )

            with st.expander("Technical Error"):
                st.code(
                    str(error),
                    language="text",
                )

            result = None
    if isinstance(result, dict):

        st.session_state["analysis_result"] = result
        st.session_state["has_analyzed"] = True

        answer = str(
            result.get(
                "answer",
                "",
            )
        ).strip()
        
        if answer:
            st.session_state["conversation_history"].append(
                {
                    "question": cleaned_question,
                    "answer": answer,
                }
            )
        if store_memory is not None:
           store_memory(
              question=cleaned_question,
              answer=answer,
    )

st.session_state["conversation_history"] = (
    st.session_state["conversation_history"][
         -MAX_CONVERSATION_HISTORY:
    ]
)
# ============================================================
# DISPLAY ANALYSIS
# ============================================================

result = st.session_state.get(
    "analysis_result"
)

has_analyzed = st.session_state.get(
    "has_analyzed",
    False,
)


if has_analyzed and isinstance(
    result,
    dict,
):

    answer = result.get(
        "answer",
        "",
    )

    sources = result.get(
        "sources",
        [],
    )

    retrieved_count = result.get(
        "retrieved_count",
        0,
    )

    used_llm = result.get(
        "used_llm",
        False,
    )

    fallback = result.get(
        "fallback",
        False,
    )
    generation_error = result.get(
        "generation_error",
        "",
    )

    tool_status = str(
        result.get(
            "tool_status",
            "",
        )
    ).upper()

    # ========================================================
    # ANALYSIS STATUS
    # ========================================================

    st.markdown("---")

    st.markdown(
        '<div class="section-title">Analysis Status</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="section-description">'
        'Execution state and evidence retrieval metadata.'
        '</div>',
        unsafe_allow_html=True,
    )

    status_col1, status_col2, status_col3 = st.columns(3)


    with status_col1:

        st.markdown(
            '<div class="status-card">'
            '<div class="status-label">Generation</div>',
            unsafe_allow_html=True,
        )

        if used_llm:

            st.markdown(
                '<div class="status-value status-ok">'
                'LLM generation used'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )

        else:

            st.markdown(
                '<div class="status-value status-neutral">'
                'LLM not used'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )
    with status_col2:

        st.markdown(
            '<div class="status-card">'
            '<div class="status-label">Response Mode</div>',
            unsafe_allow_html=True,
        )

        tool_status = str(
            result.get(
                "tool_status",
                "",
            )
        ).upper()

        if tool_status == "DENIED":

            st.markdown(
                '<div class="status-value status-warning">'
                'Request denied'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )

        elif fallback:

            st.markdown(
                '<div class="status-value status-warning">'
                'Fallback response'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )

        else:

            st.markdown(
                '<div class="status-value status-ok">'
                'Evidence grounded'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )

    with status_col3:

        st.markdown(
            '<div class="status-card">'
            '<div class="status-label">Retrieved Evidence</div>'
            f'<div class="status-value">'
            f'{retrieved_count} source(s)'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )


    # ========================================================
    # GENERATION ERROR
    # ========================================================

    if generation_error:

        st.warning(
            f"Generation note: {generation_error}"
        )


    # ========================================================
    # SECURITY ASSESSMENT
    # ========================================================

    st.markdown("---")

    st.markdown(
        '<div class="section-title">Security Assessment</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="section-description">'
        'The response below is generated from the available '
        'retrieved security evidence.'
        '</div>',
        unsafe_allow_html=True,
    )
    if answer:

        with st.container(key="answer_container"):

            st.markdown(
                '<div class="answer-header">'
                'Evidence-Grounded Assessment'
                '</div>',
                unsafe_allow_html=True,
            )

            st.markdown(answer)

    else:

        st.warning(
            "The backend returned an empty security answer."
        )

    # ========================================================
    # RETRIEVED EVIDENCE
    # ========================================================

    st.markdown("---")

    st.markdown(
        '<div class="section-title">Retrieved Evidence</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="section-description">'
        'Evidence sources returned by the local RAG backend.'
        '</div>',
        unsafe_allow_html=True,
    )

    render_sources(
        sources
    )


    # ========================================================
    # BACKEND METADATA
    # ========================================================

    st.markdown("---")

    render_metadata(
        result
    )


# ============================================================
# INITIAL STATE
# ============================================================

if not has_analyzed:

    st.info(
        "Enter a security question and click "
        "**Analyze Security Evidence** to begin."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        KiroTrace AI Security Assistant ·
        Local RAG ·
        Evidence-Grounded Security Analysis
    </div>
    """,
    unsafe_allow_html=True,
)

