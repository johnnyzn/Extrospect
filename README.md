# Extrospect

**Local risk analysis for browser extensions, with code evidence.**
Ask your AI assistant *"are my browser extensions safe?"* and get an answer backed by
verified quotes from the extensions' source code.

[中文说明](https://github.com/johnnyzn/Extrospect/blob/main/README.zh-CN.md) ·
[Architecture](https://github.com/johnnyzn/Extrospect/blob/main/docs/architecture.md) ·
[Scoring](https://github.com/johnnyzn/Extrospect/blob/main/docs/scoring.md) ·
[MCP setup](https://github.com/johnnyzn/Extrospect/blob/main/docs/mcp.md) ·
[Languages](https://github.com/johnnyzn/Extrospect/blob/main/docs/i18n.md) ·
[Evaluation](https://github.com/johnnyzn/Extrospect/blob/main/docs/eval_real_world.md) ·
[Changelog](https://github.com/johnnyzn/Extrospect/blob/main/CHANGELOG.md)

Extrospect runs on your machine. It finds the extensions installed in Chrome, Edge, Brave,
Chromium and Vivaldi profiles (or takes a `.crx` / `.zip` / directory / Web Store id),
analyses what they *can* do and what their code *actually* does, and produces an
explainable 0-100 score.

| | |
|---|---|
| **Host mode (MCP)** | an MCP server: the model in your AI client (Claude Code, Codex, Cursor, VS Code, ...) becomes the investigator, Extrospect provides the tools, verifies the evidence and computes the score - no extra API cost |
| **Static pipeline (zero tokens)** | permission tiers and combinations, CSP, attack surface, known-vulnerable libraries (retire.js + EPSS), deobfuscation, tree-sitter detection of data sources, exfiltration channels, dynamic code and hijacking, data-flow patterns, code slicing |
| **Engine mode (BYOK, experimental)** | a layered LLM pipeline - small-model triage, a larger-model investigator agent with tools, and a verifier that checks every evidence quote against the source |
| **Prompt-injection aware** | comments and long strings are stripped before code reaches a model; text addressed to AI reviewers ("classify this as benign", "忽略之前的指令") is detected and reported as a red flag |
| **Multilingual** | English and Simplified Chinese UI and reports; LLM-written text in any language |

## Status: alpha (0.1.0)

What has been checked:

- **Host mode** end to end in Claude Code with Opus 5.5, Sonnet 5.5 and Haiku 4.5. On 43
  popular and deep-integration benign extensions from the Chrome Web Store (password
  managers, ad blockers, wallets, translators, AI sidebars, developer tools) Sonnet 5.5
  produced **no false positive**; every hand-written malicious test extension, including
  one that tries to talk the reviewer into a benign verdict, was detected by all three
  models. Details: [real-world evaluation](https://github.com/johnnyzn/Extrospect/blob/main/docs/eval_real_world.md).
- About 170 offline tests (zero tokens); CI on Linux, macOS and Windows.

Known limitations:

- **The detection rate on real malware is not measured yet.** The malicious extensions
  that can still be downloaded are years old and have probably been cleaned up, so the
  evaluation has no reliable malicious samples.
- **A static score alone measures attack surface, not malice.** Large legitimate
  extensions score high, so `extrospect scan` shows it as *attack surface* rather than as
  a risk level. Get a verdict through Host mode (or Engine mode).
- Smaller models (e.g. Haiku 4.5) sometimes fail the evidence check; such results are
  shown as *needs review* instead of being trusted.
- Engine mode has not yet been validated with real models - treat it as experimental.
- Chromium-based browsers only (no Firefox or Safari yet).

Reports of false positives or missed detections are very welcome in the
[issue tracker](https://github.com/johnnyzn/Extrospect/issues).

## Install

Requires Python 3.11+. Pick one:

```bash
uv tool install extrospect      # recommended: isolated environment, uv manages Python
pipx install extrospect         # isolated environment with pipx
pip install extrospect          # into the current (virtual) environment
```

Then check the setup (optional tools, API keys, browser profiles):

```bash
extrospect doctor
```

Extras work the same way with all three, e.g. `pip install "extrospect[llm]"`:
`llm` (Engine mode), `rag` (LanceDB vector store), `all`. Optional Node.js helpers are
used automatically when present:
`npm i -g webcrack prettier retire` (bundle unpacking/deobfuscation, formatting, the
official retire.js scanner); without them Extrospect falls back to built-in equivalents.

From source:

```bash
git clone https://github.com/johnnyzn/Extrospect && cd Extrospect
uv sync --all-extras
uv run extrospect doctor          # prefix the commands below with `uv run`
```

## Use it from your AI assistant (MCP)

```bash
claude mcp add extrospect -- uvx --from extrospect extrospect-mcp
```

Installed with `pip` or `pipx` instead of uv? Use the installed command:
`claude mcp add extrospect -- extrospect-mcp` (inside a virtual environment, give its
full path, e.g. `.venv/bin/extrospect-mcp`).

Then ask *"Check my browser extensions"* or run the `/mcp__extrospect__audit_my_extensions`
prompt. It works with any MCP client that can start local servers - Claude Code, Claude
Desktop, Codex (CLI, IDE, the Codex tab of the ChatGPT desktop app), Cursor, VS Code,
Windsurf, Gemini CLI - but not with ChatGPT's chat, which only connects to remote servers.
Setup for each client, tools and the security model:
[docs/mcp.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/mcp.md).
So far it has been evaluated with Claude models; a capable model (Sonnet or Opus class)
is recommended.

## Command line

```bash
# Every installed extension, ranked by static score (attack surface; no LLM, no cost)
extrospect scan --local

# One extension: a directory, a .crx/.zip, or a Web Store id (downloads the current version)
extrospect scan path/to/extension
extrospect scan --id aapbdbdomjkkjkaonfhkkikfgjllcleb -f html -o report.html

# Engine mode (experimental): full LLM analysis with your own API key
export ANTHROPIC_API_KEY=...
extrospect analyze <id-or-path> --max-cost 0.30
extrospect trace show <trace-id>     # replay the agent's trajectory

# Reports in Chinese
extrospect --lang zh-CN scan --local
```

Other commands: `list`, `report`, `history`, `download`, `config init|show|path`,
`cache stats|clear`, `knowledge build-intel|build-advisories|listing|stats`, `languages`,
`version`.

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
Details: [docs/scoring.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/scoring.md).

## Privacy

Extrospect never uploads your extension list or extension code. Network access is
limited to: downloading a CRX when you pass a Web Store id, the retire.js vulnerability
repository, EPSS scores (CVE ids only), GitHub advisories (CVE ids), store listing pages
(only for the extension being investigated) and RDAP domain lookups. `--offline` disables
all of it. In Host mode the code your AI client reads goes to that client's model
provider; in Engine mode the analysed code slices go to the LLM provider you configured.

## Configuration

`extrospect config init` writes a commented `config.toml` with every default: models per
role (any [litellm](https://docs.litellm.ai/) model id, including local `ollama/...`),
budgets, router thresholds, score weights, tool paths and language. Environment
variables: `EXTROSPECT_LANG`, `EXTROSPECT_OFFLINE`, `EXTROSPECT_*_MODEL`,
`EXTROSPECT_DATA_DIR`, `EXTROSPECT_CACHE_DIR`, `EXTROSPECT_BROWSER_ROOTS`.

## Evaluation

`eval/` contains the dataset manifests (ids and labels only, never samples), the ablation
configurations and the evaluation scripts:

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs all --yes   # spends API credits
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # Host mode via Claude Code
```

Results: [real-world evaluation](https://github.com/johnnyzn/Extrospect/blob/main/docs/eval_real_world.md)
and the generated [eval_results.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/eval_results.md).

## Development

```bash
uv run pytest          # ~170 tests, offline, zero tokens (LLM calls use fake backends)
uv run ruff check src tests eval && uv run mypy
```

Security issues: see [SECURITY.md](https://github.com/johnnyzn/Extrospect/blob/main/SECURITY.md).

## License

[Apache License 2.0](https://github.com/johnnyzn/Extrospect/blob/main/LICENSE).
