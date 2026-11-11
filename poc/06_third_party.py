"""06 — Third-party scanners through one interface (experimental in giskard-scan).

Runs NVIDIA garak probes or DeepTeam attacks against the same target and gets
back the same ``SuiteResult``, so reports, grouping and the CI gate are shared.

Requires the optional extras:
    pip install "giskard-scan[garak]"      # and/or
    pip install "giskard-scan[deepteam]"

DeepTeam's attack generation and judging go through Giskard's default generator
(the Anthropic model set in poc/config.py), so no extra key is needed.

Usage:  python -m poc.06_third_party --tool deepteam --version v1
        python -m poc.06_third_party --tool garak --version v1
        python -m poc.06_third_party --list garak
"""

import asyncio

from poc.config import AGENT_DESCRIPTION, LANGUAGES, base_parser, configure_giskard, save_result
from target.acme_assistant import build_target


async def main() -> None:
    parser = base_parser(__doc__.splitlines()[1])
    parser.add_argument("--tool", choices=["garak", "deepteam"], default="deepteam")
    parser.add_argument("--list", choices=["giskard", "garak", "deepteam"],
                        help="List the selectable probes/attacks for a tool and exit.")
    args = parser.parse_args()

    from giskard.scan import list_scan_items, third_party_scan

    if args.list:
        for item in list_scan_items(args.list):
            print(item)
        return

    judge = configure_giskard()
    if args.tool == "deepteam":
        kwargs = dict(
            vulnerabilities=["PromptLeakage", "PIILeakage", "Misinformation"],
            attacks=["PromptInjection", "Roleplay", "LinearJailbreaking"],
            attacks_per_vulnerability_type=1,
        )
    else:  # garak: curated default probe set (bias, PII, leakage, injection, exfil)
        kwargs = dict(probes=None)

    result = await third_party_scan(
        build_target(args.version), tool=args.tool,
        description=AGENT_DESCRIPTION, languages=LANGUAGES, **kwargs,
    )
    result.print_report()
    save_result(f"06_{args.tool}_{args.version}", result, version=args.version,
                judge_model=judge, tool=args.tool)


if __name__ == "__main__":
    asyncio.run(main())
