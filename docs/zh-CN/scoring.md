# 评分

[English](../scoring.md) · 中文

最终分数由固定公式根据三个维度计算。LLM 从不直接给分；它只提交一个结论，而且结论的证据要先通过核对。

```
A    = 能力分（0-1）
Ev   = 所有 CVE 中 ( epss_percentile × reach_w ) 的最大值    reach_w：可达 1.0 / 未知 0.4 / 不可达 0.1
Em   = 经核对的 LLM malicious_prob        （Engine / Host 模式）
       GBM 概率                           （没有 LLM，但有训练好的模型）
       0.7 × LLM + 0.3 × GBM              （两者都有）
       规则基线概率                        （两者都没有）
E    = 1 - (1 - Ev)(1 - Em)               noisy-OR
Risk = 100 × A^0.5 × E^0.7 + 硬规则
```

等级：0–15 良性，16–35 低，36–60 中，61–80 高，81–100 严重。
所有指数、权重和阈值都可以在 `config.toml` 的 `[fuse]` 里配置。

## 能力分 `A`

`A = min(1, 单项权重的最大值 + 0.15 × 组合加成的个数)`。可选权限（optional）按一半权重计算。

| 权重 | 项目 |
|---|---|
| 1.0 严重 | `debugger`、`proxy`、`nativeMessaging`；全站点访问加上 `cookies`、`scripting`、`webRequest` 或 `declarativeNetRequest`；MV2 的全站点访问（可以使用 `tabs.executeScript`） |
| 0.7 高 | 单独的全部/大部分站点访问；在所有站点运行的内容脚本；`management`、`history`、`privacy`、`contentSettings`、`desktopCapture`、`tabCapture`、`browsingData`、`pageCapture`、`userScripts` 等；修改请求头的 DNR 规则；带 `unsafe-eval` 或远程脚本来源的 MV2 CSP |
| 0.4 中 | `tabs`、`webNavigation`、`downloads`、`clipboardRead`、`geolocation`、`identity`、`cookies`、`scripting`、`webRequest`、`bookmarks` 等；特定站点访问；覆盖搜索/主页/启动页；DNR 重定向；沙盒 `unsafe-eval` |
| 0.1 低 | `storage`、`alarms`、`contextMenus`、`notifications`、`activeTab`、`sidePanel` 等；`wasm-unsafe-eval` |

组合加成（每项 +0.15）：在所有站点的每个 frame 里运行内容脚本；`externally_connectable` 对所有站点开放；
web-accessible resources 对所有站点开放；在所有站点页面的 MAIN world 里运行内容脚本；从商店以外的地址更新；
剥离安全响应头的 DNR 规则；扩展页面加载远程脚本。

## 漏洞证据 `Ev`

第三方库由 retire.js 识别（CLI，或者内置的、基于其漏洞库的匹配器）。EPSS 百分位来自 FIRST；没有 EPSS 时用
严重程度代替（低 0.1、中 0.25、高 0.45、严重 0.6）。可达性一开始是"未知"；当有漏洞的库函数出现在扩展自己的
代码里时，由调查员（或 Host 模式的客户端）判定为可达或不可达。

## 恶意证据 `Em`

* **规则基线**：静态信号的 noisy-OR——敏感数据流入网络发送点、网络响应驱动代码执行、提示注入尝试、控制代理
  或调试器、篡改其他扩展、劫持搜索/请求头、远程代码、网络代码附近的大量混淆、定时触发、逃避检测。
* **GBM**：基于约 200 个静态特征的 LightGBM，按家族分组做交叉验证训练。
* **LLM**：调查员结论经核对后的 `malicious_prob`。

## 硬规则和防护

* 经核对的恶意结论，只要有至少一条核对通过的证据，分数下限为 80。
* 如果结论认为行为与声明的用途一致，**并且**接收数据的所有主机都是扩展自己的（first-party），`Em` 减半。
* **单向规则**：LLM 可以随意提高风险，但要降低较高的静态先验（≥ 0.4），必须给出经核对、用途一致、并带有证据
  的结论。
* **Verifier（核对器）**：引用必须出现在所标注的行附近（±2 行，忽略空白差异）；20 个字符以上的引用也可以
  出现在同一文件的其他位置（会更正行号）。对不上的证据会被删除；恶意结论如果因此没有证据了，会降为"可疑"并
  标记人工复核。对于能力分 ≥ 0.8、且有数据外传代码的扩展，良性结论也必须提供用途一致的证据，否则标记复核。

每份报告都会展示 `A`、`Ev`、`Em`（及其来源）、`E`、公式原始值，以及生效的硬规则。

## 结果如何标注

同一个分数，来源不同含义也不同，所以报告、CLI 和 MCP 工具（`assessment` 字段）会分别标注：

| assessment | 什么时候 | 显示为 |
|---|---|---|
| `static` | 没有模型结论（`scan`、`quick_scan`） | 攻击面：极小 / 小 / 中等 / 大 / 很大 |
| `review` | 良性或可疑结论没能降低较高的静态分（单向规则） | 需人工复核 |
| `verdict` | 通过 Verifier 核对的结论 | 良性 / 低 / 中 / 高 / 严重 |

在真实扩展上，静态分衡量的是攻击面而不是恶意：密码管理器和广告拦截器的静态分经常是 85–97
（见[真实环境评测](eval_real_world.md)），所以单独的静态分永远不会显示成风险等级。
