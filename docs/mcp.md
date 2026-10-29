# MCP server

English · [中文](zh-CN/mcp.md)

`extrospect-mcp` is a stdio MCP server. In **Host mode** the model of your MCP client
(Claude Code, Codex, Cursor, VS Code, ...) is the investigator: Extrospect provides
deterministic tools and evidence, checks the verdict and computes the score. No extra API
cost - only `full_analyze` (Engine mode) uses an API key configured for Extrospect.

## Client configuration

Extrospect is a local **stdio** server, so it works with any MCP client that can start a
local process. The command is always `uvx --from extrospect extrospect-mcp` (add options
such as `--lang zh-CN` at the end).

| Client | How to add Extrospect |
|---|---|
| Claude Code | `claude mcp add extrospect -- uvx --from extrospect extrospect-mcp` |
| Codex (CLI, IDE extension, Codex tab of the ChatGPT desktop app) | `codex mcp add extrospect -- uvx --from extrospect extrospect-mcp`, or `~/.codex/config.toml` (below) |
| Claude Desktop, Cursor, Windsurf, Gemini CLI | the `mcpServers` JSON below, in `claude_desktop_config.json`, `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json` or `~/.gemini/settings.json` |
| VS Code (Copilot agent mode) | `.vscode/mcp.json` with the `servers` JSON below |
| ChatGPT chat (web, mobile, desktop) | **not supported**: it only connects to remote HTTPS servers and cannot start local processes. Use Codex instead; do not expose Extrospect through a tunnel - it reads your local browser profiles |

`mcpServers` (Claude Desktop, Cursor, Windsurf, Gemini CLI):

```json
{
  "mcpServers": {
    "extrospect": {
      "command": "uvx",
      "args": ["--from", "extrospect", "extrospect-mcp", "--lang", "en"]
    }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{
  "servers": {
    "extrospect": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "extrospect", "extrospect-mcp", "--lang", "en"]
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.extrospect]
command = "uvx"
args = ["--from", "extrospect", "extrospect-mcp", "--lang", "en"]
```

Installed with `pip` or `pipx` instead of uv? Replace `uvx --from extrospect extrospect-mcp`
with `extrospect-mcp` everywhere above (inside a virtual environment, its full path, e.g.
`/path/to/.venv/bin/extrospect-mcp`). If a desktop app reports that the command cannot be
found (GUI apps often do not see your shell `PATH`), use the absolute path printed by
`which uvx` or `which extrospect-mcp`. From a source checkout, use
`uv --directory /path/to/Extrospect run extrospect-mcp` as the command instead.

**Models.** The tools work with any model that supports tool calling (Claude, GPT,
Gemini, ...), but so far Extrospect has only been evaluated with Claude Opus 5.5, Sonnet
5.5 and Haiku 4.5 ([evaluation](eval_real_world.md)). A capable model is recommended.
Evidence checks and scoring run on the server, so a weaker model cannot lower a score
without verified evidence - its results are shown as *needs review* instead. Clients
differ in which MCP features they support: where the `audit_my_extensions` prompt is not
available (in Claude Code it is `/mcp__extrospect__audit_my_extensions`), simply ask
the assistant to check your browser extensions.

Server options: `--lang <code>` (language of explanations and reports), `--offline` (no
network), `--allow-download` (let `quick_scan` fetch extensions that are not installed).
For `full_analyze`, add the API key to the server environment, e.g.
`"env": {"ANTHROPIC_API_KEY": "..."}`.

## Tools

| Tool | Purpose |
|---|---|
| `list_installed_extensions` | Extensions in local browser profiles (id, name, version, browser, profile, enabled) |
| `quick_scan(ext_id)` | Static analysis: score (`assessment: static` - attack surface, not a verdict), capability flags, suspicious code, CVEs, remote hosts, slices to investigate |
| `get_slices(ext_id, top)` | The most dangerous code slices with gutter line numbers |
| `read_file(ext_id, path, start_line, end_line)` | Up to 200 sanitised lines of a file |
| `search_code(ext_id, pattern)` | Regex search (libraries excluded by default) |
| `get_callers(ext_id, function)` | Definitions and call sites of a function |
| `decode_string(ext_id, value, method)` | base64 / hex / charcode / url / unicode / rot13 / xor; retrieve elided strings (`sha:<id>`) |
| `lookup_domain(ext_id, domain)` | First-party or third-party, known category, registration age (RDAP) |
| `retrieve_listing(ext_id)` | Store listing: declared purpose, developer, website, users, data disclosures |
| `retrieve_similar_malware(code)` | Known malicious techniques similar to a snippet |
| `retrieve_advisory(cve)` | Advisory: summary, affected functions, exploitation conditions |
| `submit_verdict(ext_id, ...)` | Verdict + evidence; quotes are verified against the source, the score is computed server-side (`assessment: verdict` or `review`, with `action_required` when a resubmission is needed) |
| `full_analyze(ext_id)` | Engine mode (layered LLM pipeline, BYOK) |

Prompt: `audit_my_extensions(language)` - the investigation procedure.
Resource: `extrospect://report/{ext_id}` - the latest report (Markdown).

## Security model

* Tools accept extension ids, never arbitrary paths; file arguments are confined to the
  extension's analysis workspace (path traversal is rejected).
* Read-only: nothing is installed, changed or removed.
* Code and listing texts are returned sanitised (comments removed, long strings elided)
  inside `<untrusted_code>` markers; text that addresses AI reviewers is redacted.
* `submit_verdict` evidence must quote the code verbatim; invented quotes are dropped and a
  `malicious` verdict without verifiable evidence is downgraded. A benign verdict lowers a
  high static score only with `purpose_consistent=true` and a verified quote; otherwise
  the result is marked `needs review` and `action_required` tells the model how to
  resubmit.
* Nothing about your installed extensions is sent anywhere (see the README's privacy section).
