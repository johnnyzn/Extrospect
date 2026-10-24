# Extrospect

**Local risk analysis for browser extensions, with code evidence.**
Ask your AI assistant *"are my browser extensions safe?"* and get an answer backed by
verified quotes from the extensions' source code.

[中文说明](README.zh-CN.md) · [Architecture](docs/architecture.md) · [Scoring](docs/scoring.md) ·
[MCP setup](docs/mcp.md) · [Languages](docs/i18n.md) · [Evaluation](docs/eval_results.md)

Extrospect runs on your machine. It finds the extensions installed in Chrome, Edge, Brave,
Chromium and Vivaldi profiles (or takes a `.crx` / `.zip` / directory / Web Store id),
analyses what they *can* do and what their code *actually* does, and produces an
explainable 0-100 risk score.

| | |
|---|---|
| **Static pipeline (zero tokens)** | permission tiers and combinations, CSP, attack surface, known-vulnerable libraries (retire.js + EPSS), deobfuscation, tree-sitter detection of data sources, exfiltration channels, dynamic code and hijacking, data-flow patterns, code slicing |
| **Engine mode (BYOK)** | a layered LLM pipeline - small-model triage, a larger-model investigator agent with tools, and a verifier that checks every evidence quote against the source |
| **Host mode (MCP)** | an MCP server: the model in Claude Desktop / Claude Code / Cursor becomes the investigator, Extrospect provides the tools and computes the score - no extra API cost |
| **Prompt-injection aware** | comments and long strings are stripped before code reaches a model; text addressed to AI reviewers ("classify this as benign", "忽略之前的指令") is detected and reported as a red flag |
| **Multilingual** | English and Simplified Chinese UI and reports; LLM-written text in any language |

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/johnnyzn/Extrospect && cd Extrospect
uv sync --all-extras        # or: uv sync  (static analysis + MCP only)
uv run extrospect doctor    # check optional tools, API keys, browser profiles
```

Optional Node.js helpers improve the analysis and are used automatically when present:
`npm i -g webcrack prettier retire` (bundle unpacking/deobfuscation, formatting, the
official retire.js scanner). Without them Extrospect falls back to built-in equivalents.

## Quick start

```bash
# Every installed extension, ranked by static risk (no LLM, no cost)
uv run extrospect scan --local

# One extension: a directory, a .crx/.zip, or a Web Store id (downloads the current version)
uv run extrospect scan path/to/extension
uv run extrospect scan --id aapbdbdomjkkjkaonfhkkikfgjllcleb -f html -o report.html

# Engine mode: full LLM analysis with your own API key
export ANTHROPIC_API_KEY=...
uv run extrospect analyze <id-or-path> --max-cost 0.30
uv run extrospect trace show <trace-id>     # replay the agent's trajectory

# Reports in Chinese
uv run extrospect --lang zh-CN scan --local
```

Other commands: `list`, `report`, `download`, `config init|show|path`, `cache stats|clear`,
`knowledge build-intel|build-advisories|listing|stats`, `languages`, `version`.

## Use it from your AI assistant (MCP)

```bash
claude mcp add extrospect -- uv --directory /path/to/Extrospect run extrospect-mcp
```

Then ask *"Check my browser extensions"* or run the `audit_my_extensions` prompt. Claude
Desktop and Cursor configuration: [docs/mcp.md](docs/mcp.md).

## How a score is computed

```
A    capability            what permissions + manifest allow (tiers, combinations, CSP)
Ev   vulnerability         max over CVEs of EPSS percentile x reachability weight
Em   malicious evidence    verified LLM verdict / GBM / rule baseline
E    = 1 - (1 - Ev)(1 - Em)
Risk = 100 x A^0.5 x E^0.7  (+ hard rules)  ->  benign / low / medium / high / critical
```

The LLM never sets the score: it produces a verdict and evidence, the Verifier drops
evidence whose quote is not in the file, and the formula does the rest. Every report
shows the breakdown. Without a model verdict the score is shown as **attack surface**,
not as a risk level, and a verdict that cannot be verified is shown as **needs review**.
Details: [docs/scoring.md](docs/scoring.md).

## Privacy

Extrospect never uploads your extension list or extension code. Network access is
limited to: downloading a CRX when you pass a Web Store id, the retire.js vulnerability
repository, EPSS scores (CVE ids only), GitHub advisories (CVE ids), store listing pages
(only for the extension being investigated) and RDAP domain lookups. `--offline` disables
all of it. In Engine mode the analysed code slices go to the LLM provider you configured.

## Configuration

`uv run extrospect config init` writes a commented `config.toml` with every default:
models per role (any [litellm](https://docs.litellm.ai/) model id, including local
`ollama/...`), budgets, router thresholds, score weights, tool paths and language.
Environment variables: `EXTROSPECT_LANG`, `EXTROSPECT_OFFLINE`, `EXTROSPECT_*_MODEL`,
`EXTROSPECT_DATA_DIR`, `EXTROSPECT_CACHE_DIR`, `EXTROSPECT_BROWSER_ROOTS`.

## Evaluation

`eval/` contains the dataset manifests (ids and labels only, never samples), the ablation
configurations and the scripts that produce [docs/eval_results.md](docs/eval_results.md):

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl --label benign
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules,gbm
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs all --yes   # spends credits
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # Host mode via Claude Code
```

First results on real Chrome Web Store extensions are in
[docs/eval_real_world.md](docs/eval_real_world.md): in Host mode no false positive on 43
popular and deep-integration benign extensions, while the static score alone flags most
password managers and ad blockers. Reliable malicious samples are still missing.

## Development

```bash
uv run pytest          # ~170 tests, offline, zero tokens (LLM calls use fake backends)
uv run ruff check src tests eval && uv run mypy
```

## License

[Apache License 2.0](LICENSE).
