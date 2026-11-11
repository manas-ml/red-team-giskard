"""Shared configuration for the POC scripts.

* Points Giskard's attacker / judge LLM at Anthropic.
* Provides local embeddings for the knowledge base (Anthropic has no
  embeddings endpoint, and Giskard's knowledge-base generators need vectors).
* Helpers to persist results to ``reports/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Opt out of Giskard's anonymous telemetry before it is imported.
os.environ.setdefault("DO_NOT_TRACK", "1")

import numpy as np  # noqa: E402

try:  # .env is optional
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Giskard's own LLM (scenario generation, attacker turns, LLM-as-judge).
# Giskard always sends temperature=1.0; Claude Sonnet 5.5 accepts that default
# value, whereas Claude Opus 5.5 rejects sampling parameters entirely.
DEFAULT_GISKARD_MODEL = "anthropic/claude-sonnet-5-5"

AGENT_DESCRIPTION = (
    "AcmeBank Assistant: a customer-support chatbot for a retail bank. It answers "
    "questions about AcmeBank products (fees, savings rates, cards, transfers) "
    "and can look up the logged-in customer's own account balance with a tool. "
    "It must never disclose internal configuration, other customers' data, or "
    "give personalised financial, legal or medical advice."
)
LANGUAGES = ["en"]


def configure_giskard() -> str:
    """Set Giskard's default generator to an Anthropic model and return its id."""
    from giskard.checks import set_default_generator

    model = os.getenv("GISKARD_MODEL", DEFAULT_GISKARD_MODEL)
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("WARNING: ANTHROPIC_API_KEY is not set; LLM calls will fail.", file=sys.stderr)
    set_default_generator(model)
    return model


# ------------------------------------------------------------------ embeddings
_TOKEN_RE = re.compile(r"[a-z0-9$%.]+")


def local_embedding(text: str, dim: int = 512) -> list[float]:
    """Deterministic hashed bag-of-words (uni+bigram) embedding, L2-normalised.

    Good enough for Giskard's nearest-neighbour document grouping on a small KB,
    with zero extra dependencies or API calls.
    """
    tokens = _TOKEN_RE.findall(text.lower())
    grams = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
    vec = np.zeros(dim, dtype=float)
    for gram in grams:
        h = int.from_bytes(hashlib.md5(gram.encode()).digest()[:8], "little")
        vec[h % dim] += 1.0 if (h >> 63) == 0 else -1.0
    norm = np.linalg.norm(vec)
    return (vec / norm if norm else vec).tolist()


def build_knowledge_base():
    from giskard.scan import Document, KnowledgeBase

    from target.knowledge_base import FAQ_DOCUMENTS

    return KnowledgeBase(
        documents=tuple(
            Document(content=doc, embeddings=local_embedding(doc)) for doc in FAQ_DOCUMENTS
        )
    )


# ---------------------------------------------------------------------- CLI
def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--version", choices=["v1", "v2"], default="v1",
                        help="Target agent version to attack (default: v1).")
    parser.add_argument("--max-scenarios", type=int, default=20,
                        help="Total scenario budget (controls cost).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--concurrency", type=int, default=4)
    return parser


# ------------------------------------------------------------------ reporting
def summarize(result: Any, group_key: str = "threat-type") -> dict[str, Any]:
    """Turn a Giskard SuiteResult into a compact, JSON-serialisable summary."""
    grouped = result.group_by(group_key)
    groups = {
        str(name): {
            "passed": g.passed,
            "failed": g.failed,
            "errored": g.errored,
            "skipped": g.skipped,
            "pass_rate": g.pass_rate,
        }
        for name, g in grouped.groups.items()
    }
    failures = []
    for scenario in result.failures_and_errors:
        turns = [
            {"user": str(i.inputs), "assistant": str(i.outputs)}
            for i in scenario.final_trace.interactions
        ]
        failures.append(
            {
                "scenario": scenario.scenario_name,
                "status": str(scenario.status.value if hasattr(scenario.status, "value") else scenario.status),
                "tags": list(scenario.tags),
                "conversation": turns,
            }
        )
    return {
        "passed": result.passed_count,
        "failed": result.failed_count,
        "errored": result.errored_count,
        "skipped": result.skipped_count,
        "pass_rate": result.pass_rate,
        "groups": groups,
        "failures": failures,
        "recommendation": getattr(result, "recommendation", None),
    }


def save_result(name: str, result: Any, group_key: str = "threat-type", **meta: Any) -> Path:
    """Write summary JSON + JUnit XML for a SuiteResult under reports/."""
    summary = summarize(result, group_key)
    summary["meta"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "group_key": group_key,
        **meta,
    }
    path = REPORTS / f"{name}.json"
    path.write_text(json.dumps(summary, indent=2, default=str))
    result.to_junit_xml(REPORTS / f"{name}.junit.xml")
    print(f"\nSaved {path} and {name}.junit.xml")
    return path
