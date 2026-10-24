# MCP server

`extrospect-mcp` is a stdio MCP server. In **Host mode** the model of your MCP client
(Claude Desktop, Claude Code, Cursor, ...) is the investigator: Extrospect provides
deterministic tools and evidence, checks the verdict and computes the score. No extra API
cost - only `full_analyze` (Engine mode) uses an API key configured for Extrospect.

## Client configuration

Until Extrospect is published on PyPI, run it from your checkout with `uv`:

**Claude Code**

```bash
claude mcp add extrospect -- uv --directory /path/to/Extrospect run extrospect-mcp
```

**Claude Desktop** (`claude_desktop_config.json`) and **Cursor** (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "extrospect": {
      "command": "uv",
      "args": ["--directory", "/path/to/Extrospect", "run", "extrospect-mcp", "--lang", "en"]
    }
  }
}
```

After publication the command becomes `uvx --from extrospect extrospect-mcp`.

Server options: `--lang <code>` (language of explanations and reports), `--offline` (no
network), `--allow-download` (let `quick_scan` fetch extensions that are not installed).
For `full_analyze`, add the API key to the server environment, e.g.
`"env": {"ANTHROPIC_API_KEY": "..."}`.

## Tools

| Tool | Purpose |
|---|---|
| `list_installed_extensions` | Extensions in local browser profiles (id, name, version, browser, profile, enabled) |
| `quick_scan(ext_id)` | Static analysis: score, capability flags, suspicious code, CVEs, remote hosts, slices to investigate |
| `get_slices(ext_id, top)` | The most dangerous code slices with gutter line numbers |
| `read_file(ext_id, path, start_line, end_line)` | Up to 200 sanitised lines of a file |
| `search_code(ext_id, pattern)` | Regex search (libraries excluded by default) |
| `get_callers(ext_id, function)` | Definitions and call sites of a function |
| `decode_string(ext_id, value, method)` | base64 / hex / charcode / url / unicode / rot13 / xor; retrieve elided strings (`sha:<id>`) |
| `lookup_domain(ext_id, domain)` | First-party or third-party, known category, registration age (RDAP) |
| `retrieve_listing(ext_id)` | Store listing: declared purpose, developer, website, users, data disclosures |
| `retrieve_similar_malware(code)` | Known malicious techniques similar to a snippet |
| `retrieve_advisory(cve)` | Advisory: summary, affected functions, exploitation conditions |
| `submit_verdict(ext_id, ...)` | Verdict + evidence; quotes are verified against the source, the score is computed server-side |
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
