# Architecture

```
                 ┌──────────────────────────────────────────────┐
 AI client ────▶ │ extrospect-mcp (MCPServer, stdio)            │
 (Host mode)     │ tools / prompt / resource                    │
                 └───────────────┬──────────────────────────────┘
 CLI ────────────────────────────┤
                                 ▼
┌──────────────────────────────── extrospect ─────────────────────────────────┐
│ acquire        static pipeline              LLM pipeline (Engine)     fuse   │
│ profiles  ──▶  manifest/permissions/CSP ─▶ Router #1 ─▶ Triage ─▶      score │
│ CRX/zip        retire.js + EPSS            (small model)  │           report │
│                view: strip libs, unpack,                  ▼                  │
│                deobfuscate, format         Router #2 ─▶ Investigator ◀─ RAG  │
│                tree-sitter sinks + slices  (large model + tools)             │
│                sanitise (anti-injection)               ▼                     │
│                                            Verifier ───────────────▶ fuse    │
│ cache (SQLite): file scans, triage, reports, EPSS/listings/RDAP/advisories   │
│ knowledge: RAG-A listings · RAG-B malware intel · RAG-C advisories (LanceDB) │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Modules

| Package | Responsibility |
|---|---|
| `acquire/` | local profile discovery, Web Store CRX download, CRX2/CRX3 parsing and safe unpacking |
| `static/manifest.py` | lenient JSON, MV2/MV3 normalisation, `__MSG_*__` resolution in the user's language |
| `static/permissions.py`, `csp.py`, `surface.py` | capability profile `A`, attack surface, per-file execution context |
| `static/vulns.py` | retire.js CLI or built-in matcher, EPSS enrichment |
| `workspace.py` | the normalised *view* every later stage uses (see below) |
| `static/jsparse.py`, `sinks.py` | tree-sitter parsing, callee normalisation (aliases, `browser.*`), sink rules, flow patterns, endpoints |
| `static/slicer.py` | function-centred slices with same-file callers, merged and size-limited |
| `llm/sanitize.py` | comment stripping, string elision, injection detection, `<untrusted_code>` wrapping |
| `llm/` | client (litellm), routers, triage, tools, investigator, verifier, engine, fake backends |
| `knowledge/` | listings (RAG-A), intel (RAG-B), advisories (RAG-C), embeddings, vector store |
| `baseline/` | rule baseline and LightGBM |
| `fuse.py`, `report.py`, `pipeline.py`, `cli.py` | scoring, rendering, orchestration, CLI |
| `extrospect_mcp/` | MCP server |

## Two modes, one tool layer

* **Engine mode** (`extrospect analyze`, MCP `full_analyze`): Extrospect runs the agent
  loop with your API key (BYOK). Funnel: every stage reduces what the next, more
  expensive stage sees - static analysis decides whether an LLM is needed at all, triage
  batches slices for a small model, only suspicious extensions reach the investigator.
* **Host mode** (MCP): the client's model runs the loop with the same tools; Extrospect
  verifies the submitted verdict and computes the score.

The tool layer (`llm/tools.py`) is shared, so both modes see identical, sanitised data.

## The analysis view

Before any code is parsed, the extension is copied into a workspace keyed by its content
hash: minified files are formatted, bundles are unpacked into modules
(`file.js@modules/...`) and obfuscated code is deobfuscated (webcrack), inline `<script>`
blocks become `page.html.inline-N.js`, and identified third-party libraries are stripped
unless they call sensitive extension APIs. Ordinary files are kept byte-for-byte, so line
numbers match the extension folder. All line numbers in slices, LLM evidence and the
Verifier refer to this view.

## Defence against prompt injection

1. Comments are removed and strings longer than 200 characters are replaced by
   `<STR len=N sha=...>` placeholders before code reaches any model; line numbers are kept.
2. Code is wrapped in `<untrusted_code>` blocks that the code cannot close; system prompts
   state that code is data.
3. Strings and comments addressing AI reviewers are detected (English, Chinese, Japanese,
   Korean, Spanish, French, German, Russian), hidden from models and reported as a red flag.
4. Model output is schema-validated; free text never feeds the score.
5. The one-way rule and the Verifier limit what a manipulated model could change.

## Caching and cost control

| Layer | Key |
|---|---|
| file scans | `sha256(view file)` + analyser version + context |
| triage | `(slice_id, prompt version, model, language)` with slice-relative evidence lines |
| reports | `(extension id, version, pipeline version, mode)` |
| prompt caching | system prompt + first user message marked as cache breakpoints (Anthropic models) |
| listings / EPSS / RDAP / advisories | key-value cache with TTLs |

Budgets: investigator steps, input tokens and cost per investigation, plus a hard cost cap
per extension. Every model call and tool step is written to a JSONL trace
(`extrospect trace show <id>` replays the trajectory).
