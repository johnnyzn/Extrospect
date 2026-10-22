# Extrospect

Local risk analysis for browser extensions, with code evidence.

> Status: under active development (v1 milestones in progress).

```bash
uv sync
uv run extrospect scan --local          # static scan of every installed extension (zero tokens)
uv run extrospect scan path/to/extension
uv run extrospect --lang zh-CN scan path/to/extension.crx
```
