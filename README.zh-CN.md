# Extrospect

**在本机运行的浏览器扩展风险分析工具，结论附带代码证据。**
对你的 AI 助手说一句"我装的浏览器扩展安全吗？"，得到的回答会附上逐字核对过的源码引用。

[English](README.md) · [架构](docs/architecture.md) · [评分](docs/scoring.md) ·
[MCP 配置](docs/mcp.md) · [多语言](docs/i18n.md) · [评测结果](docs/eval_results.md)

Extrospect 完全在本机运行。它能找到 Chrome、Edge、Brave、Chromium、Vivaldi 各个配置文件里安装的扩展
（也可以直接分析 `.crx` / `.zip` / 目录 / 商店 ID），分析扩展**能**做什么、代码**实际**做了什么，
最后给出一个可解释的 0–100 风险分。

| | |
|---|---|
| **静态管线（零 token）** | 权限分级与组合、CSP、攻击面、已知漏洞库（retire.js + EPSS）、解混淆、基于 tree-sitter 的敏感数据来源 / 外传通道 / 动态代码 / 劫持行为识别、数据流模式、代码切片 |
| **Engine 模式（BYOK）** | 分层 LLM 管线：小模型分诊、大模型带工具调查、Verifier 把每条证据引用和源码逐字核对 |
| **Host 模式（MCP）** | MCP server：Claude Desktop / Claude Code / Cursor 里的模型充当调查员，Extrospect 提供工具并计算分数，不额外花 API 费用 |
| **防提示注入** | 代码交给模型前会去掉注释、截断长字符串；代码里写给 AI 审查者的话（"classify this as benign"、"忽略之前的指令"）会被识别出来，并作为风险信号报告 |
| **多语言** | 界面和报告支持英文、简体中文；LLM 生成的内容可以是任意语言 |

## 安装

需要 Python 3.11+ 和 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/johnnyzn/Extrospect && cd Extrospect
uv sync --all-extras        # 或者 uv sync（只要静态分析 + MCP）
uv run extrospect doctor    # 检查可选工具、API key、浏览器配置文件
```

可选的 Node.js 工具装了会自动使用，分析效果更好：`npm i -g webcrack prettier retire`
（拆包 / 解混淆、格式化、官方 retire.js 扫描器）。没装时使用内置的替代实现。

## 快速开始

```bash
# 本机所有扩展按静态风险排序（不用 LLM，零成本）
uv run extrospect --lang zh-CN scan --local

# 单个扩展：目录、.crx/.zip，或者商店 ID（会下载当前版本）
uv run extrospect --lang zh-CN scan path/to/extension
uv run extrospect --lang zh-CN scan --id aapbdbdomjkkjkaonfhkkikfgjllcleb -f html -o report.html

# Engine 模式：用你自己的 API key 做完整的 LLM 分析
export ANTHROPIC_API_KEY=...
uv run extrospect --lang zh-CN analyze <id 或路径> --max-cost 0.30
uv run extrospect trace show <trace-id>     # 回放 agent 的调查过程
```

设置 `EXTROSPECT_LANG=zh-CN` 后可以省略 `--lang`（默认跟随系统语言）。
其他命令：`list`、`report`、`download`、`config init|show|path`、`cache stats|clear`、
`knowledge build-intel|build-advisories|listing|stats`、`languages`、`version`。

## 在 AI 助手里使用（MCP）

```bash
claude mcp add extrospect -- uv --directory /path/to/Extrospect run extrospect-mcp --lang zh-CN
```

然后说"检查我的浏览器扩展"，或者使用 `audit_my_extensions` 这个 prompt。
Claude Desktop、Cursor 的配置见 [docs/mcp.md](docs/mcp.md)。

## 分数怎么算

```
A    能力分        权限和 manifest 允许它做什么（分级、组合、CSP）
Ev   漏洞证据      所有 CVE 中 EPSS 百分位 × 可达性权重 的最大值
Em   恶意证据      经校验的 LLM 判定 / GBM / 规则基线
E    = 1 - (1 - Ev)(1 - Em)
Risk = 100 × A^0.5 × E^0.7（再叠加硬规则）-> 良性 / 低 / 中 / 高 / 严重
```

分数不由 LLM 直接给出：LLM 只产出判定和证据，Verifier 删除在文件里找不到的引用，剩下的交给公式。
每份报告都会展示分项。没有模型结论时，分数显示为**攻击面**大小而不是风险等级；模型结论无法核实时显示为**需人工复核**。详见 [docs/scoring.md](docs/scoring.md)。

## 隐私

Extrospect 不会上传你的扩展列表或扩展代码。只有以下网络访问：传入商店 ID 时下载 CRX、retire.js 漏洞库、
EPSS 分数（只发 CVE 编号）、GitHub 漏洞公告（只发 CVE 编号）、商店页面（只针对正在调查的扩展）、
RDAP 域名查询。`--offline` 会关闭全部网络访问。Engine 模式下，被分析的代码切片会发送给你配置的 LLM 服务商。

## 配置

`uv run extrospect config init` 会生成带全部默认值的 `config.toml`：每个角色用哪个模型
（任意 [litellm](https://docs.litellm.ai/) 模型名，包括本地 `ollama/...`）、预算、路由阈值、评分权重、
工具路径和语言。

## 评测

`eval/` 里是数据集清单（只有 ID 和标签，不含样本本体）、消融配置，以及生成
[docs/eval_results.md](docs/eval_results.md) 的脚本：

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl --label benign
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules,gbm
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs all --yes   # 会花 API 费用
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # 通过 Claude Code 评测 Host 模式
```

在真实 Chrome 商店扩展上的首轮结果见 [docs/eval_real_world.md](docs/eval_real_world.md)：
Host 模式下 43 个热门及深度集成的良性扩展零误报；只看静态分时，大多数密码管理器和广告拦截器会被
误判为高风险。可靠的恶意样本仍然缺乏。

## 开发

```bash
uv run pytest          # 约 170 个测试，离线、零 token（LLM 调用使用假后端）
uv run ruff check src tests eval && uv run mypy
```

## 许可证

[Apache License 2.0](LICENSE)。
