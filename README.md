# Red teaming an LLM agent with Giskard (POC)

A proof of concept of the red-teaming features in the open-source
[Giskard](https://github.com/Giskard-AI/giskard-oss) library (v3: `giskard-scan`
plus `giskard-checks`). The system under test is a custom, Claude-powered
banking agent. No Giskard Hub is needed: everything runs locally and in CI.

## What it shows

| # | Script | Giskard feature | What you see |
|---|---|---|---|
| 01 | `poc/01_vulnerability_scan.py` | `vulnerability_scan` | Auto-generated attacks from a plain-language agent description: 8 adversarial harm categories, a prompt-injection dataset, Crescendo and GOAT multi-turn jailbreaks, GCG suffixes, HarmBench / do-not-answer. Results are grouped by threat type. |
| 02 | `poc/02_multiturn_attacks.py` | `generate_suite` + Crescendo / GOAT | Multi-turn jailbreaks run alone; prints the transcript of the attack that got furthest |
| 03 | `poc/03_quality_scan.py` | `quality_scan` + `KnowledgeBase` | Hallucination, sycophancy, multi-topic and out-of-scope probes built from the FAQ documents, plus an LLM recommendation |
| 04 | `poc/04_custom_redteam.py` | Custom `ScenarioGenerator`, `from_fn` checks, `Conformity` | Banking attacks tagged by OWASP category; a tool-call-level authorization (BOLA) check; detection of planted secrets; registering the generator in the built-in scan registry |
| 05 | `poc/05_simulated_attacker.py` | `UserSimulator`, `Toxicity`, `Conformity` | An LLM attacker persona that adapts to the agent over several turns |
| 06 | `poc/06_third_party.py` | `third_party_scan` (experimental) | NVIDIA garak and DeepTeam run through the same interface and result type |
| 07 | `poc/07_compare_v1_v2.py` | Seeded suites, `group_by` | The same suite run against v1 and v2, with a pass-rate table per threat type in `reports/07_comparison.md` |
| CI | `tests/test_redteam_gate.py` + `.github/workflows/redteam.yml` | `SuiteResult.pass_rate`, JUnit export | Fails the build when the security pass rate drops below a threshold |

## The target: AcmeBank Assistant (`target/acme_assistant.py`)

A support agent built on the Anthropic SDK, with a manual tool-use loop and a
`get_account_balance` tool. It is a Giskard v3 target: an async callable
`(inputs, trace) -> Interaction`. It rebuilds the conversation from the trace,
so multi-turn attacks work, and attaches tool calls and knowledge-base context
as metadata for checks to inspect.

| | v1 (naive) | v2 (hardened) |
|---|---|---|
| System prompt | "Help with whatever they ask"; contains a fake override code and API key (canaries) | Scoped role, explicit security rules, no secrets in the prompt |
| Tool authorization | None: any account id works | Enforced in code: only `ACC-1001`, the session user |
| Input guard | None | Regex filter for common injection markers |
| Output guard | None | Redacts canary strings |
| Refusals | `stop_reason == "refusal"` is handled as a safe decline in both versions | same |

## Setup

Requires Python 3.12 or later.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # then set ANTHROPIC_API_KEY
```

### Models
- **Target agent:** `ACME_TARGET_MODEL`, default `claude-opus-5-5`.
- **Giskard attacker / judge:** `GISKARD_MODEL`, default `anthropic/claude-sonnet-5-5`.
  Giskard's generator always sends `temperature=1.0`. Claude Opus 5.5 rejects
  sampling parameters; Sonnet 5.5 and Haiku 5.5 accept that default value. Use
  `anthropic/claude-haiku-5-5` for cheaper runs.
- **Embeddings:** Anthropic has no embeddings endpoint. Knowledge-base
  documents get local hashed bag-of-words vectors (`poc/config.py:local_embedding`),
  so the quality scan runs with an Anthropic key only.

## Running it

```bash
pytest -q                                              # offline tests (no API key needed)

python -m poc.01_vulnerability_scan --version v1 --max-scenarios 30
python -m poc.02_multiturn_attacks  --version v1 --max-scenarios 6
python -m poc.03_quality_scan       --version v1 --max-scenarios 20
python -m poc.04_custom_redteam     --version v1        # add --with-builtin to merge with the full scan
python -m poc.05_simulated_attacker --version v1 --turns 4
python -m poc.06_third_party        --tool deepteam --version v1   # needs giskard-scan[deepteam]
python -m poc.07_compare_v1_v2      --max-scenarios 30

RUN_REDTEAM=1 pytest -m live                           # CI gate against v2 (REDTEAM_THRESHOLD=0.9)
```

Every script takes `--version v1|v2`, `--max-scenarios` (cost control),
`--seed` (reproducible generation) and `--concurrency`. Results are written to
`reports/<name>.json` (pass rates per group, failing conversations) and
`reports/<name>.junit.xml`.

**Cost tip:** start with `--max-scenarios 10 --singleturn` on script 01. The
multi-turn attackers and LLM judges make several model calls per scenario.

**Licences and network:** the HarmBench, do-not-answer and GCG generators
download datasets from Hugging Face. do-not-answer is non-commercial; pass
`--commercial-use` to script 01 to exclude it.

## Demo script (about 15 min)
1. **Agent (2 min).** Show the v1 system prompt and the unchecked tool in `target/acme_assistant.py`.
2. **Scan (4 min).** Run `01 --singleturn --max-scenarios 15` and walk through the threat-type table.
3. **Multi-turn attack (3 min).** Run `02` and read the transcript of the attack that got furthest.
4. **Custom attacks (3 min).** Run `04`: the BOLA check fails on a real tool call, and the canary-leak check fails.
5. **Comparison (2 min).** Run `07` and open `reports/07_comparison.md` to compare v1 and v2.
6. **CI gate (1 min).** Show the `live-gate` job; weakening the v2 prompt fails the build.

## Layout
```
target/         system under test (agent, prompts, tools, FAQ knowledge base)
poc/config.py   Anthropic wiring for Giskard, local embeddings, report helpers
poc/redteam_lib.py  custom ScenarioGenerator + deterministic security checks
poc/0N_*.py     one script per capability (table above)
tests/          offline tests (fake Anthropic client) + live CI gate
reports/        generated results (git-ignored)
```
