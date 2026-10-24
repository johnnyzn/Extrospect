# 架构

[English](../architecture.md) · 中文

```
                 ┌──────────────────────────────────────────────┐
 AI 客户端 ────▶ │ extrospect-mcp（MCPServer，stdio）           │
 （Host 模式）   │ tools / prompt / resource                    │
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

## 模块

| 包 | 职责 |
|---|---|
| `acquire/` | 发现本机浏览器配置文件、从商店下载 CRX、解析 CRX2/CRX3 并安全解包 |
| `static/manifest.py` | 宽松的 JSON 解析、MV2/MV3 归一化、按用户语言解析 `__MSG_*__` |
| `static/permissions.py`、`csp.py`、`surface.py` | 能力分 `A`、攻击面、每个文件的执行上下文 |
| `static/vulns.py` | retire.js CLI 或内置匹配器、EPSS 数据补充 |
| `workspace.py` | 之后各阶段统一使用的归一化*视图*（见下文） |
| `static/jsparse.py`、`sinks.py` | tree-sitter 解析、调用名归一化（别名、`browser.*`）、sink 规则、数据流模式、外联地址 |
| `static/slicer.py` | 以函数为中心的代码切片，包含同文件的调用者，合并并限制大小 |
| `llm/sanitize.py` | 去注释、省略长字符串、检测注入、包上 `<untrusted_code>` |
| `llm/` | 客户端（litellm）、路由、分诊、工具、调查员、核对器、引擎、假后端 |
| `knowledge/` | 商店页面（RAG-A）、恶意手法情报（RAG-B）、漏洞公告（RAG-C）、向量化、向量库 |
| `baseline/` | 规则基线和 LightGBM |
| `fuse.py`、`report.py`、`pipeline.py`、`cli.py` | 评分、渲染、流程编排、命令行 |
| `extrospect_mcp/` | MCP server |

## 两种模式，同一套工具

* **Engine 模式**（`extrospect analyze`、MCP 的 `full_analyze`）：Extrospect 用你的 API key（BYOK）自己跑
  agent 循环。漏斗式处理：每一级都减少下一级（更贵的一级）要看的内容——静态分析决定是否需要 LLM，分诊把代码
  切片打包交给小模型，只有可疑的扩展才会进入调查员。
* **Host 模式**（MCP）：客户端的模型用同一套工具跑循环；Extrospect 核对它提交的结论并计算分数。

工具层（`llm/tools.py`）是共用的，所以两种模式看到的数据完全一样，都经过净化。

## 分析视图

在解析任何代码之前，扩展会被复制到一个以内容哈希命名的工作区：压缩过的文件会被格式化，打包文件会拆成模块
（`file.js@modules/...`），混淆代码会被还原（webcrack），内联的 `<script>` 块变成 `page.html.inline-N.js`，
识别出的第三方库会被剥离（除非它们调用了敏感的扩展 API）。普通文件按原样保留，所以行号和扩展目录里的一致。
代码切片、LLM 证据和 Verifier 里的所有行号都以这个视图为准。

## 防提示注入

1. 代码交给任何模型之前，会去掉注释，并把超过 200 个字符的字符串替换成 `<STR len=N sha=...>` 占位符；行号不变。
2. 代码被包在 `<untrusted_code>` 块里，代码本身无法闭合这个块；系统提示明确说明代码只是数据。
3. 检测写给 AI 审查者的字符串和注释（英文、中文、日文、韩文、西班牙文、法文、德文、俄文），对模型隐藏，并作为
   风险信号报告。
4. 模型输出按 schema 校验；自由文本从不参与计分。
5. 单向规则和 Verifier 限制了被操纵的模型能改变的东西。

## 缓存和成本控制

| 层 | 缓存键 |
|---|---|
| 文件扫描 | `sha256(视图文件)` + 分析器版本 + 执行上下文 |
| 分诊 | `(slice_id, 提示词版本, 模型, 语言)`，证据行号相对于切片 |
| 报告 | `(扩展 ID, 版本, 管线版本, 模式)` |
| 提示缓存 | 系统提示和第一条用户消息标记为缓存断点（Anthropic 模型） |
| 商店页面 / EPSS / RDAP / 漏洞公告 | 带 TTL 的键值缓存 |

预算：调查员的步数、每次调查的输入 token 和费用，以及每个扩展的硬性费用上限。每次模型调用和工具调用都会写入
JSONL 轨迹（`extrospect trace show <id>` 可以回放调查过程）。
