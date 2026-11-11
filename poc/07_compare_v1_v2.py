"""07 — Measure the fix: run the same seeded suite against v1 and v2.

Builds the suite once (custom bank attacks + Giskard's prompt-injection dataset +
LLM-generated adversarial scenarios), then runs the same scenario definitions
against both versions, so differences come from the defences rather than from
different tests. (LLM-driven attacker turns still adapt to each agent's replies.) Writes a Markdown comparison to reports/07_comparison.md.

Usage:  python -m poc.07_compare_v1_v2 --max-scenarios 30
"""

import asyncio
import json

from poc.config import (
    AGENT_DESCRIPTION,
    LANGUAGES,
    REPORTS,
    base_parser,
    configure_giskard,
    save_result,
    summarize,
)
from poc.redteam_lib import BankAttackScenarioGenerator
from target.acme_assistant import build_target


def _rate(stats: dict | None) -> str:
    if not stats or stats.get("pass_rate") is None:
        return "n/a"
    return f"{stats['pass_rate'] * 100:.0f}% ({stats['passed']}/{stats['passed'] + stats['failed'] + stats['errored']})"


async def main() -> None:
    parser = base_parser(__doc__.splitlines()[1])
    parser.add_argument("--singleturn", action="store_true")
    args = parser.parse_args()
    judge = configure_giskard()

    from giskard.scan import (
        AdversarialScenarioGenerator,
        PromptInjectionScenarioGenerator,
        generate_suite,
    )

    suite = await generate_suite(
        description=AGENT_DESCRIPTION,
        languages=LANGUAGES,
        generators=[BankAttackScenarioGenerator, PromptInjectionScenarioGenerator,
                    AdversarialScenarioGenerator],
        max_scenarios=args.max_scenarios,
        seed=args.seed,
        target_mode="singleturn" if args.singleturn else "multiturn",
    )
    print(f"Suite: {len(suite.scenarios)} scenarios (same definitions for both versions)")

    summaries = {}
    for version in ("v1", "v2"):
        print(f"\n######## Running against {version} ########")
        result = await suite.run(build_target(version), parallel=True,
                                 max_concurrency=args.concurrency, return_exception=True)
        result.print_report(group_by="threat-type")
        save_result(f"07_suite_{version}", result, version=version, judge_model=judge)
        summaries[version] = summarize(result)

    v1, v2 = summaries["v1"], summaries["v2"]
    groups = sorted(set(v1["groups"]) | set(v2["groups"]))
    lines = [
        "# AcmeBank Assistant: v1 vs v2 red-team results",
        "",
        f"Judge / attacker model: `{judge}`, seed {args.seed}, {len(suite.scenarios)} scenarios.",
        "",
        "| Threat type | v1 pass rate | v2 pass rate |",
        "|---|---|---|",
    ]
    for g in groups:
        lines.append(f"| {g} | {_rate(v1['groups'].get(g))} | {_rate(v2['groups'].get(g))} |")
    lines.append(f"| **Overall** | **{_rate(v1)}** | **{_rate(v2)}** |")
    out = REPORTS / "07_comparison.md"
    out.write_text("\n".join(lines) + "\n")
    (REPORTS / "07_comparison.json").write_text(json.dumps(summaries, indent=2, default=str))
    print("\n" + "\n".join(lines))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    asyncio.run(main())
