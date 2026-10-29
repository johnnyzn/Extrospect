# MCP server

[English](../mcp.md) · 中文

`extrospect-mcp` 是一个 stdio 方式的 MCP server。在 **Host 模式**下，你的 MCP 客户端（Claude Code、
Codex、Cursor、VS Code 等）里的模型就是调查员：Extrospect 提供确定性的工具和证据，核对结论并计算分数。
不额外产生 API 费用——只有 `full_analyze`（Engine 模式）会用到给 Extrospect 配置的 API key。

## 客户端配置

Extrospect 是一个本地 **stdio** server，只要 MCP 客户端能启动本机进程就能用。启动命令始终是
`uvx --from extrospect extrospect-mcp`（`--lang zh-CN` 之类的参数加在最后）。

| 客户端 | 添加方法 |
|---|---|
| Claude Code | `claude mcp add extrospect -- uvx --from extrospect extrospect-mcp --lang zh-CN` |
| Codex（CLI、IDE 插件、ChatGPT 桌面版里的 Codex 标签页） | `codex mcp add extrospect -- uvx --from extrospect extrospect-mcp --lang zh-CN`，或者写进 `~/.codex/config.toml`（见下文） |
| Claude Desktop、Cursor、Windsurf、Gemini CLI | 把下面的 `mcpServers` JSON 写进 `claude_desktop_config.json`、`~/.cursor/mcp.json`、`~/.codeium/windsurf/mcp_config.json` 或 `~/.gemini/settings.json` |
| VS Code（Copilot agent 模式） | 在 `.vscode/mcp.json` 里写下面的 `servers` JSON |
| ChatGPT 聊天（网页、手机、桌面版） | **不支持**：它只能连接远程 HTTPS server，不能启动本机进程。请改用 Codex；也不要通过内网穿透把 Extrospect 暴露出去——它会读取你本机的浏览器配置文件 |

`mcpServers`（Claude Desktop、Cursor、Windsurf、Gemini CLI）：

```json
{
  "mcpServers": {
    "extrospect": {
      "command": "uvx",
      "args": ["--from", "extrospect", "extrospect-mcp", "--lang", "zh-CN"]
    }
  }
}
```

VS Code（`.vscode/mcp.json`）：

```json
{
  "servers": {
    "extrospect": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "extrospect", "extrospect-mcp", "--lang", "zh-CN"]
    }
  }
}
```

Codex（`~/.codex/config.toml`）：

```toml
[mcp_servers.extrospect]
command = "uvx"
args = ["--from", "extrospect", "extrospect-mcp", "--lang", "zh-CN"]
```

没装 uv、用 `pip` 或 `pipx` 安装的话，把上面所有的 `uvx --from extrospect extrospect-mcp` 换成 `extrospect-mcp`
（装在虚拟环境里时写完整路径，例如 `/path/to/.venv/bin/extrospect-mcp`）。如果桌面应用提示找不到命令（图形界面程序
常常读不到终端里的 `PATH`），就改用 `which uvx` 或 `which extrospect-mcp` 输出的完整路径。
从源码运行时，把命令换成 `uv --directory /path/to/Extrospect run extrospect-mcp`。

**关于模型。** 这些工具适用于任何支持工具调用的模型（Claude、GPT、Gemini 等），但目前只用 Claude Opus 5.5、
Sonnet 5.5、Haiku 4.5 做过评测（见[真实环境评测](eval_real_world.md)），建议使用能力较强的模型。证据核对和计分
都在服务器端完成，较弱的模型拿不出核验通过的证据，就无法拉低分数，这时结果会显示为"需人工复核"。各客户端支持的
MCP 功能不完全相同：用不了 `audit_my_extensions` 这个 prompt 时（在 Claude Code 里是
`/mcp__extrospect__audit_my_extensions`），直接让助手"检查我的浏览器扩展"即可。

服务器参数：`--lang <code>`（解释和报告的语言）、`--offline`（不联网）、`--allow-download`（允许
`quick_scan` 下载本机没装的扩展）。使用 `full_analyze` 时，把 API key 加到服务器的环境变量里，例如
`"env": {"ANTHROPIC_API_KEY": "..."}`。

## 工具

| 工具 | 用途 |
|---|---|
| `list_installed_extensions` | 本机浏览器配置文件里的扩展（ID、名称、版本、浏览器、配置文件、是否启用） |
| `quick_scan(ext_id)` | 静态分析：分数（`assessment: static`——表示攻击面，不是结论）、能力标记、可疑代码、CVE、远程主机、待调查的代码切片 |
| `get_slices(ext_id, top)` | 最危险的代码切片，带行号 |
| `read_file(ext_id, path, start_line, end_line)` | 读取文件，最多 200 行，已做净化处理 |
| `search_code(ext_id, pattern)` | 正则搜索（默认排除第三方库） |
| `get_callers(ext_id, function)` | 函数的定义和调用位置 |
| `decode_string(ext_id, value, method)` | base64 / hex / charcode / url / unicode / rot13 / xor 解码；取回被省略的长字符串（`sha:<id>`） |
| `lookup_domain(ext_id, domain)` | 域名是扩展自己的还是第三方的、已知类别、注册时长（RDAP） |
| `retrieve_listing(ext_id)` | 商店页面信息：声明的用途、开发者、网站、用户数、数据披露 |
| `retrieve_similar_malware(code)` | 与一段代码相似的已知恶意手法 |
| `retrieve_advisory(cve)` | 漏洞公告：摘要、受影响的函数、利用条件 |
| `submit_verdict(ext_id, ...)` | 提交结论和证据；引用会和源码核对，分数在服务器端计算（`assessment: verdict` 或 `review`，需要重新提交时会带 `action_required`） |
| `full_analyze(ext_id)` | Engine 模式（分层 LLM 管线，BYOK） |

Prompt：`audit_my_extensions(language)`——调查流程。
Resource：`extrospect://report/{ext_id}`——最新的报告（Markdown）。

## 安全模型

* 工具只接受扩展 ID，不接受任意路径；文件参数被限制在该扩展的分析工作区里（拒绝路径穿越）。
* 只读：不会安装、修改或删除任何东西。
* 代码和商店文字返回前会做净化（去掉注释、省略长字符串），并放在 `<untrusted_code>` 标记里；写给 AI 审查者
  的文字会被遮蔽。
* `submit_verdict` 的证据必须逐字引用代码；编造的引用会被删除，没有可核对证据的"恶意"结论会被降级。良性结论
  要降低较高的静态分，必须设置 `purpose_consistent=true` 并有核对通过的引用；否则结果标记为"需人工复核"，
  并通过 `action_required` 告诉模型怎样重新提交。
* 你装了哪些扩展，不会发送到任何地方（见 README 的隐私部分）。
