"""04 — Custom, domain-specific red teaming.

Shows how to extend Giskard with your own threat model:

* a custom ``ScenarioGenerator`` (poc/redteam_lib.py) with OWASP-tagged banking
  attacks, including a multi-turn privilege-escalation conversation;
* deterministic checks over the *trace*, including tool-call metadata (a real
  BOLA check, not just text matching) and planted canary secrets;
* an LLM judge (``Conformity``) per attack, with the rule in plain language.

With --with-builtin the custom generator is registered next to Giskard's
built-in vulnerability generators, so one scan runs both.

Usage:  python -m poc.04_custom_redteam --version v1
        python -m poc.04_custom_redteam --version v1 --with-builtin --max-scenarios 30
"""

import asyncio

from poc.config import AGENT_DESCRIPTION, LANGUAGES, base_parser, configure_giskard, save_result
from poc.redteam_lib import BankAttackScenarioGenerator
from target.acme_assistant import build_target


async def main() -> None:
    parser = base_parser(__doc__.splitlines()[1])
    parser.add_argument("--with-builtin", action="store_true",
                        help="Register the custom generator into the full vulnerability scan.")
    parser.set_defaults(max_scenarios=None)
    args = parser.parse_args()
    judge = configure_giskard()
    target = build_target(args.version)

    if args.with_builtin:
        from giskard.scan import vulnerability_scan, vulnerability_suite_generator_registry

        vulnerability_suite_generator_registry.register(BankAttackScenarioGenerator)
        result = await vulnerability_scan(
            target=target, description=AGENT_DESCRIPTION, languages=LANGUAGES,
            max_scenarios=args.max_scenarios, seed=args.seed,
            max_concurrency=args.concurrency, return_exception=True,
        )
        name = f"04_custom_plus_builtin_{args.version}"
    else:
        from giskard.scan import generate_suite

        suite = await generate_suite(
            description=AGENT_DESCRIPTION, languages=LANGUAGES,
            generators=[BankAttackScenarioGenerator], max_scenarios=args.max_scenarios,
            seed=args.seed,
        )
        result = await suite.run(target, parallel=True, max_concurrency=args.concurrency,
                                 return_exception=True)
        result.print_report(group_by="owasp")
        name = f"04_custom_redteam_{args.version}"

    save_result(name, result, group_key="owasp", version=args.version, judge_model=judge)


if __name__ == "__main__":
    asyncio.run(main())
