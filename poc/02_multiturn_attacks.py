"""02 — Multi-turn jailbreaks in isolation (Crescendo + GOAT via generate_suite).

Single-prompt tests miss attacks that escalate over several turns. This script
builds a suite from only the two multi-turn attacker generators, so you can show
complete attack transcripts where the agent gives in at turn 3 or 4.

It also shows the composable layer under the scan: ``generate_suite`` gives you
a ``Suite`` you can inspect, filter or re-run before it touches the target.

Usage:  python -m poc.02_multiturn_attacks --version v1 --max-scenarios 8
"""

import asyncio

from poc.config import AGENT_DESCRIPTION, LANGUAGES, base_parser, configure_giskard, save_result
from target.acme_assistant import build_target


async def main() -> None:
    args = base_parser(__doc__.splitlines()[1]).parse_args()
    judge = configure_giskard()

    from giskard.scan import (
        CrescendoAttackScenarioGenerator,
        GOATAttackScenarioGenerator,
        generate_suite,
    )

    suite = await generate_suite(
        description=AGENT_DESCRIPTION,
        languages=LANGUAGES,
        generators=[CrescendoAttackScenarioGenerator, GOATAttackScenarioGenerator],
        max_scenarios=args.max_scenarios,
        seed=args.seed,
        target_mode="multiturn",
    )
    print(f"Generated {len(suite.scenarios)} multi-turn attack scenarios:")
    for scenario in suite.scenarios:
        print(f"  - {scenario.name}")

    result = await suite.run(
        build_target(args.version),
        parallel=True,
        max_concurrency=args.concurrency,
        return_exception=True,
    )
    result.print_report(group_by="threat-type")

    # Print the longest successful attack transcript (the demo money shot).
    failures = sorted(result.failures_and_errors,
                      key=lambda s: len(s.final_trace.interactions), reverse=True)
    if failures:
        worst = failures[0]
        print(f"\n=== Successful attack: {worst.scenario_name} ===")
        for n, turn in enumerate(worst.final_trace.interactions, 1):
            print(f"\n[turn {n}] ATTACKER: {turn.inputs}\n[turn {n}] AGENT: {turn.outputs}")

    save_result(f"02_multiturn_attacks_{args.version}", result,
                version=args.version, judge_model=judge, seed=args.seed)


if __name__ == "__main__":
    asyncio.run(main())
