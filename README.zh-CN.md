# Extrospect

**在本机运行的浏览器扩展风险分析工具，结论附带代码证据。**
对你的 AI 助手说一句"我装的浏览器扩展安全吗？"，得到的回答会附上逐字核对过的源码引用。

[English](https://github.com/johnnyzn/Extrospect/blob/main/README.md) ·
[架构](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/architecture.md) ·
[评分](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/scoring.md) ·
[MCP 配置](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/mcp.md) ·
[多语言](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/i18n.md) ·
[评测](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/eval_real_world.md) ·
[更新日志](https://github.com/johnnyzn/Extrospect/blob/main/CHANGELOG.md)

Extrospect 完全在本机运行。它能找到 Chrome、Edge、Brave、Chromium、Vivaldi 各个配置文件里安装的扩展
（也可以直接分析 `.crx` / `.zip` / 目录 / 商店 ID），分析扩展**能**做什么、代码**实际**做了什么，
最后给出一个可解释的 0–100 分。

| | |
|---|---|
| **Host 模式（MCP）** | MCP server：Claude Code / Claude Desktop / Cursor 里的模型充当调查员，Extrospect 提供工具、核对证据并计算分数，不额外花 API 费用 |
| **静态管线（零 token）** | 权限分级与组合、CSP、攻击面、已知漏洞库（retire.js + EPSS）、解混淆、基于 tree-sitter 的敏感数据来源 / 外传通道 / 动态代码 / 劫持行为识别、数据流模式、代码切片 |
| **Engine 模式（BYOK，实验性）** | 分层 LLM 管线：小模型分诊、大模型带工具调查、Verifier 把每条证据引用和源码逐字核对 |
| **防提示注入** | 代码交给模型前会去掉注释、截断长字符串；代码里写给 AI 审查者的话（"classify this as benign"、"忽略之前的指令"）会被识别出来，并作为风险信号报告 |
| **多语言** | 界面和报告支持英文、简体中文；LLM 生成的内容可以是任意语言 |

## 现状：alpha（0.1.0）

已经验证过的：

- **Host 模式**在 Claude Code 里用 Opus 5.5、Sonnet 5.5、Haiku 4.5 完整跑通。Chrome 商店里 43 个热门及
  深度集成的良性扩展（密码管理器、广告拦截器、加密钱包、翻译、AI 侧边栏、开发者工具），Sonnet 5.5
  **零误报**；手写的恶意测试扩展（包括一个想说服审查者判为良性的）三个模型全部识别出来。
  详见[真实环境评测](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/eval_real_world.md)。
- 约 170 个离线测试（零 token）；CI 覆盖 Linux、macOS、Windows。

已知局限：

- **对真实恶意软件的检出率还没有测出来。** 现在还能下载到的恶意扩展都是几年前上报的，很可能已经洗白，
  评测里缺少可靠的恶意样本。
- **只看静态分时，它衡量的是攻击面，不代表恶意。** 大型正常扩展的静态分往往很高，所以 `extrospect scan`
  把它显示为"攻击面"而不是风险等级。要得到判定结论，请用 Host 模式（或 Engine 模式）。
- 较小的模型（例如 Haiku 4.5）有时过不了证据核对，这类结果会显示为"需人工复核"，不会被直接采信。
- Engine 模式还没有用真实模型验证过，请当作实验功能。
- 只支持 Chromium 系浏览器（暂不支持 Firefox、Safari）。

欢迎在 [issue](https://github.com/johnnyzn/Extrospect/issues) 里反馈误报或漏报。

## 安装

需要 Python 3.11+。

```bash
uv tool install extrospect        # 或者 pipx install extrospect / pip install extrospect
extrospect doctor                 # 检查可选工具、API key、浏览器配置文件
```

可选依赖：`extrospect[llm]`（Engine 模式）、`extrospect[rag]`（LanceDB 向量库）、`extrospect[all]`。
可选的 Node.js 工具装了会自动使用：`npm i -g webcrack prettier retire`（拆包 / 解混淆、格式化、
官方 retire.js 扫描器）；没装时使用内置的替代实现。

从源码运行：

```bash
git clone https://github.com/johnnyzn/Extrospect && cd Extrospect
uv sync --all-extras
uv run extrospect doctor          # 下面的命令前面都加上 `uv run`
```

## 在 AI 助手里使用（MCP）

```bash
claude mcp add extrospect -- uvx --from extrospect extrospect-mcp --lang zh-CN
```

然后说"检查我的浏览器扩展"，或者运行 `/mcp__extrospect__audit_my_extensions` 这个 prompt。
Claude Desktop、Cursor 的配置、工具列表和安全模型见
[docs/zh-CN/mcp.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/mcp.md)。
建议使用能力较强的模型（Sonnet 或 Opus 级别）。

## 命令行

```bash
# 本机所有扩展按静态分（攻击面）排序（不用 LLM，零成本）
extrospect --lang zh-CN scan --local

# 单个扩展：目录、.crx/.zip，或者商店 ID（会下载当前版本）
extrospect --lang zh-CN scan path/to/extension
extrospect --lang zh-CN scan --id aapbdbdomjkkjkaonfhkkikfgjllcleb -f html -o report.html

# Engine 模式（实验性）：用你自己的 API key 做完整的 LLM 分析
export ANTHROPIC_API_KEY=...
extrospect --lang zh-CN analyze <id 或路径> --max-cost 0.30
extrospect trace show <trace-id>     # 回放 agent 的调查过程
```

设置 `EXTROSPECT_LANG=zh-CN` 后可以省略 `--lang`（默认跟随系统语言）。
其他命令：`list`、`report`、`history`、`download`、`config init|show|path`、`cache stats|clear`、
`knowledge build-intel|build-advisories|listing|stats`、`languages`、`version`。

## 分数怎么算

```
A    能力分        权限和 manifest 允许它做什么（分级、组合、CSP）
Ev   漏洞证据      所有 CVE 中 EPSS 百分位 × 可达性权重 的最大值
Em   恶意证据      经校验的 LLM 判定 / GBM / 规则基线
E    = 1 - (1 - Ev)(1 - Em)
Risk = 100 × A^0.5 × E^0.7（再叠加硬规则）-> 良性 / 低 / 中 / 高 / 严重
```

分数不由 LLM 直接给出：LLM 只产出判定和证据，Verifier 删除在文件里找不到的引用，剩下的交给公式。
每份报告都会展示分项。没有模型结论时，分数显示为**攻击面**大小而不是风险等级；模型结论无法核实时显示为
**需人工复核**。详见 [docs/zh-CN/scoring.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/scoring.md)。

## 隐私

Extrospect 不会上传你的扩展列表或扩展代码。只有以下网络访问：传入商店 ID 时下载 CRX、retire.js 漏洞库、
EPSS 分数（只发 CVE 编号）、GitHub 漏洞公告（只发 CVE 编号）、商店页面（只针对正在调查的扩展）、
RDAP 域名查询。`--offline` 会关闭全部网络访问。Host 模式下，你的 AI 客户端读到的代码会发送给该客户端的
模型服务商；Engine 模式下，被分析的代码切片会发送给你配置的 LLM 服务商。

## 配置

`extrospect config init` 会生成带全部默认值的 `config.toml`：每个角色用哪个模型（任意
[litellm](https://docs.litellm.ai/) 模型名，包括本地 `ollama/...`）、预算、路由阈值、评分权重、工具路径和语言。
环境变量：`EXTROSPECT_LANG`、`EXTROSPECT_OFFLINE`、`EXTROSPECT_*_MODEL`、`EXTROSPECT_DATA_DIR`、
`EXTROSPECT_CACHE_DIR`、`EXTROSPECT_BROWSER_ROOTS`。

## 评测

`eval/` 里是数据集清单（只有 ID 和标签，不含样本本体）、消融配置和评测脚本：

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs all --yes   # 会花 API 费用
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # 通过 Claude Code 评测 Host 模式
```

结果见[真实环境评测](https://github.com/johnnyzn/Extrospect/blob/main/docs/zh-CN/eval_real_world.md)
和自动生成的 [eval_results.md](https://github.com/johnnyzn/Extrospect/blob/main/docs/eval_results.md)。

## 开发

```bash
uv run pytest          # 约 170 个测试，离线、零 token（LLM 调用使用假后端）
uv run ruff check src tests eval && uv run mypy
```

安全问题的报告方式见 [SECURITY.md](https://github.com/johnnyzn/Extrospect/blob/main/SECURITY.md)。

## 许可证

[Apache License 2.0](https://github.com/johnnyzn/Extrospect/blob/main/LICENSE)。
