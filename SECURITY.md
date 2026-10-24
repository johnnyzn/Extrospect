# Security policy / 安全政策

## Reporting a vulnerability / 报告漏洞

**English.** Please report security vulnerabilities privately through GitHub's
**"Report a vulnerability"** button in this repository's *Security* tab, not in a public
issue. You will get an answer within a week. Relevant examples:

- an MCP tool reading or writing files outside the extension's analysis workspace;
- anything that executes code from an analysed extension (Extrospect only reads code);
- network requests beyond those documented in the README's privacy section;
- a way for an analysed extension to change the score or verdict despite the Verifier and
  the one-way rule (prompt-injection bypasses).

Missed detections and false positives are not vulnerabilities - please open a normal
issue with the extension id.

**中文。** 请通过本仓库 *Security* 标签页里的 **"Report a vulnerability"** 按钮私下报告安全漏洞，
不要发公开 issue。一周内会回复。例如：

- MCP 工具能读写扩展分析工作区以外的文件；
- 任何会执行被分析扩展代码的情况（Extrospect 只读取代码）；
- README 隐私部分列出的范围以外的网络请求；
- 被分析的扩展能绕过 Verifier 和单向规则改变分数或结论（绕过提示注入防护）。

漏报和误报不属于安全漏洞，请带上扩展 ID 发普通 issue。

## Supported versions / 支持的版本

Only the latest release receives fixes. / 只有最新版本会收到修复。
