# 真实环境评测（2026-10-23）

[English](../eval_real_world.md) · 中文

这是第一次在从 Chrome 应用商店下载的真实扩展上做评测，用来补充手写样本的冒烟测试。管线版本
`0.1.0+p1`，判定阈值：分数 ≥ 61（高或严重）算作"被标记"。

## 样本

用 `eval/fetch_samples.py` 下载 `eval/datasets/seed.jsonl` 里的 210 个 ID：

| 子集 | ID 数 | 能下载 | 说明 |
|---|---|---|---|
| malicious（恶意） | 164 | 56 | 55 个来自同一个家族（`palant-2023-06-cluster`），1 个来自 `extension-games-cluster` |
| benign_hard（难判断的良性） | 23 | 23 | 密码管理器、广告拦截器、加密钱包、翻译、AI 侧边栏、开发者工具 |
| benign（良性） | 23 | 20 | 常用的热门扩展 |

**关于标签的提醒。** 所有恶意 ID 都来自 2023 年的"疑似恶意"名单。商店只提供扩展的*当前*版本，所以能下载的
这 56 个，是又在商店里存活了三年的扩展，现在的代码可能已经没有当初被列入名单的内容了。因此在它们上面测出的
检出率并不可靠。良性标签（知名开发者）是可靠的，所以下面的误报率才是站得住的数字。

## 结果

**静态管线**（`run_eval.py --configs rules`，零 token，全部 99 个样本）：见
[eval_results.md](../eval_results.md)。

| 子集 | 数量 | 被静态分标记 |
|---|---|---|
| benign_hard | 23 | 16（69.6%） |
| benign | 20 | 5（25.0%） |
| malicious（标签不可靠） | 56 | 24（42.9%） |

AUC 0.470：在真实扩展上，静态分区分不开两类。规则信号在大型正常扩展上触发得至少和在名单扩展上一样多
（`link_rewrite`：良性 79%，名单 64%；`time_bomb`：58% 对 30%；`exfiltration_pattern`：35% 对 34%）。

**Host 模式**（`eval/run_host_eval.py`：由 Claude 模型通过 Claude Code 调用 MCP server，每个扩展一个全新会话）：
59 个样本（名单上的 16 个，加全部 43 个良性），外加 7 个手写样本，分别用 Claude Sonnet 5.5 和 Claude Haiku 4.5。

| 分数来源 | 数量 | 精确率 | 召回率 | 误报率 | 难良性误报率 | AUC |
|---|---|---|---|---|---|---|
| 静态分（quick_scan），同样 59 个 | 59 | 25.0% | 43.8% | 48.8% | 69.6% | 0.475 |
| Host，Sonnet 5.5 | 59 | 100.0% | 6.2% | **0.0%** | **0.0%** | 0.971 |
| Host，Haiku 4.5 | 59 | 72.7% | 50.0% | 7.0% | 13.0% | 0.895 |
| Host，手写样本（4 个恶意含提示注入，3 个良性），两个模型都是 | 7 | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |

- 43 个良性扩展最终都是良性或低（最高分 34），其中包括静态分 87–97 的 12 个（1Password、Ghostery、Keeper、
  Stylus、Dashlane、Wappalyzer、Privacy Badger、Tampermonkey、Adobe Acrobat、AdBlock、Bitwarden、Adblock Plus）。
- 名单上的 16 个，最终结论是 1 个恶意、3 个可疑、12 个良性。看模型给出的证据，它们的现版本大多像普通工具
  （其中一个有未声明的数据收集问题）。名单样本的排名仍然整体高于良性样本（AUC 0.971），但这测不出检出率。
- 所有手写样本，包括提示注入那个，Sonnet 5.5 和 Haiku 4.5 都判对了（之前的人工测试用的是 Opus 5.5）。
- Haiku 4.5 的 3 个误报（1Password 95、Privacy Badger 89、MetaMask 76）结论其实都是*良性*：它没有设置
  `purpose_consistent=true`，部分证据引用的是商店页面文字而不是代码，所以单向规则保留了静态分，并把报告
  标记为需人工复核。安全机制按设计工作了，但结果看起来像"结论良性、分数严重"。它在名单样本上更高的"召回率"
  也来自同一条规则，而不是真的发现了问题。
- 按 API 价格计算的成本：Sonnet 5.5 每个扩展 $0.26（约 10 轮工具调用、36 秒）；Haiku 4.5 $0.08（9 轮、52 秒）。

## 发现并修复的 bug

- 分析 LastPass、Dashlane、MetaMask 时静态分析崩溃（解码后的字符串里有孤立的代理字符）。
- Adblock Plus、AdBlock、Keeper 超过 200 MB 的解包上限而被拒绝；上限改为 1 GiB，另加压缩比检查防止压缩炸弹。

## 尚未解决

1. **可靠的恶意样本。** 需要恶意*历史版本*的存档（研究机构的存档，用 `fetch_samples.py --import-dir` 导入），
   或者经人工确认的近期上报扩展。
2. **静态分校准。** 在真实扩展上，静态分衡量的是攻击面，不是恶意程度。这次评测之后，只有静态分析的结果
   改为显示"攻击面"而不是风险等级；重新校准规则权重需要可靠的恶意样本（见第 1 条）。
3. **较弱的模型。** 这次评测之后，`submit_verdict` 会预先说明"用途一致"规则，结论无法采纳时返回
   `action_required`，这类结果显示为"需人工复核"。尚未重新测量。
4. **其他客户端。** 目前只测了 Claude Code（Claude Desktop、Cursor 还没测）。

## 复现

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # 会消耗 Claude 额度
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --report
```
