# MCP server

[English](../mcp.md) · 中文

`extrospect-mcp` 是一个 stdio 方式的 MCP server。在 **Host 模式**下，你的 MCP 客户端（Claude Desktop、
Claude Code、Cursor 等）里的模型就是调查员：Extrospect 提供确定性的工具和证据，核对结论并计算分数。
不额外产生 API 费用——只有 `full_analyze`（Engine 模式）会用到给 Extrospect 配置的 API key。

## 客户端配置

**Claude Code**

```bash
claude mcp add extrospect -- uvx --from extrospect extrospect-mcp --lang zh-CN
```

**Claude Desktop**（`claude_desktop_config.json`）和 **Cursor**（`~/.cursor/mcp.json`）：

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

从源码运行时，把命令换成 `uv --directory /path/to/Extrospect run extrospect-mcp`。在 Claude Code 里，
prompt 可以用 `/mcp__extrospect__audit_my_extensions` 调用。建议使用能力较强的模型（Sonnet 或 Opus 级别）：
较小的模型更容易过不了证据核对，这时结果会显示为"需人工复核"。

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
