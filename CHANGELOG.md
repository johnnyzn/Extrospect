# Changelog / 更新日志

## 0.1.1 - 2026-10-29

Found by installing 0.1.0 from PyPI with pip and testing every command. / 用 pip 从 PyPI 安装 0.1.0 并逐项测试时发现。

**English**

- CLI: text in square brackets was swallowed by the terminal renderer (rich markup). Code
  snippets lost parts such as `[type=password]`, and install hints showed
  `pip install 'extrospect'` instead of `'extrospect[llm]'`. Markup is now off for all
  output, so extension names, code and model-written text print verbatim and can no
  longer inject terminal styling.
- README: pip users install into a virtual environment; Debian/Ubuntu system Python needs
  `python3-venv` (PEP 668).

**中文**

- 命令行：方括号里的文字会被终端渲染库（rich 的标记语法）吞掉。代码片段会丢失 `[type=password]` 这类内容，
  安装提示显示成 `pip install 'extrospect'` 而不是 `'extrospect[llm]'`。现在所有输出都关闭了标记解析，扩展名、
  代码和模型写的文字都会原样显示，也无法再借此伪造终端样式。
- README：pip 用户请装进虚拟环境；Debian、Ubuntu 的系统 Python 需要先安装 `python3-venv`（PEP 668）。

## 0.1.0 - 2026-10-23 (alpha)

First public release. / 首次公开发布。

**English**

- Local risk analysis of Chromium-based browser extensions (Chrome, Edge, Brave, Chromium,
  Vivaldi), or of a `.crx` / `.zip` / directory / Chrome Web Store id: CLI `extrospect`
  and MCP server `extrospect-mcp`.
- Static pipeline (zero tokens): permission tiers and combinations, CSP, attack surface,
  known-vulnerable libraries (retire.js + EPSS), bundle unpacking and deobfuscation,
  tree-sitter sink detection, data-flow patterns, code slicing, prompt-injection detection.
- Host mode: the MCP client's model investigates with 13 tools, an `audit_my_extensions`
  prompt and report resources; evidence quotes are verified and the score is computed
  server-side.
- Engine mode (experimental, BYOK): layered LLM pipeline through litellm - triage,
  investigator agent, verifier.
- Knowledge bases: store listings, malware-technique intel, security advisories.
- Results are labelled by what produced them: static-only scores are shown as attack
  surface, verdicts that cannot be verified as "needs review".
- English and Simplified Chinese interface, reports and documentation.
- Evaluation harness, including Host-mode evaluation through Claude Code, and a first
  real-world evaluation (`docs/eval_real_world.md`).

**中文**

- 在本机分析 Chromium 系浏览器（Chrome、Edge、Brave、Chromium、Vivaldi）里安装的扩展，也可以分析
  `.crx` / `.zip` / 目录 / Chrome 商店 ID：命令行 `extrospect` 和 MCP server `extrospect-mcp`。
- 静态管线（零 token）：权限分级与组合、CSP、攻击面、已知漏洞库（retire.js + EPSS）、拆包和解混淆、
  基于 tree-sitter 的 sink 检测、数据流模式、代码切片、提示注入检测。
- Host 模式：MCP 客户端的模型用 13 个工具、`audit_my_extensions` prompt 和报告资源做调查；证据引用的核对和
  分数计算都在服务器端完成。
- Engine 模式（实验性，BYOK）：通过 litellm 的分层 LLM 管线——分诊、调查员 agent、核对器。
- 知识库：商店页面、恶意手法情报、安全公告。
- 结果按来源标注：只有静态分析时显示为攻击面，无法核实的结论显示为"需人工复核"。
- 英文和简体中文的界面、报告和文档。
- 评测框架，包括通过 Claude Code 做的 Host 模式评测，以及首轮真实环境评测（`docs/zh-CN/eval_real_world.md`）。
