"""03 — Knowledge-base quality scan (giskard.scan.quality_scan, successor of RAGET).

Generates probes from the agent's FAQ documents and checks the answers:

* Hallucination  — questions whose answer is in the KB; is the answer correct?
* Sycophancy     — the user pushes a false premise; does the agent cave?
* Split / multi-topic questions — compositional questions across documents
* Out-of-scope   — questions the KB cannot answer; does the agent make things up?

The scan finishes with an LLM-written recommendation for each failing component.
Embeddings are computed locally (see poc/config.py) because Anthropic does not
offer an embeddings endpoint.

Usage:  python -m poc.03_quality_scan --version v1 --max-scenarios 20
"""

import asyncio

from poc.config import (
    AGENT_DESCRIPTION,
    LANGUAGES,
    base_parser,
    build_knowledge_base,
    configure_giskard,
    save_result,
)
from target.acme_assistant import build_target


async def main() -> None:
    args = base_parser(__doc__.splitlines()[1]).parse_args()
    judge = configure_giskard()

    from giskard.scan import quality_scan

    result = await quality_scan(
        target=build_target(args.version),
        description=AGENT_DESCRIPTION,
        languages=LANGUAGES,
        knowledge_base=build_knowledge_base(),
        max_scenarios=args.max_scenarios,
        seed=args.seed,
        group_by="component",
        parallel=True,
        max_concurrency=args.concurrency,
        return_exception=True,
    )
    save_result(f"03_quality_scan_{args.version}", result, group_key="component",
                version=args.version, judge_model=judge, seed=args.seed)


if __name__ == "__main__":
    asyncio.run(main())
