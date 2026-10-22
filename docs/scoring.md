# Scoring

The final score is computed by a fixed formula from three dimensions. The LLM never
sets the score directly; it contributes a verdict whose evidence is verified first.

```
A    = capability score (0-1)
Ev   = max over CVEs ( epss_percentile x reach_w )     reach_w: yes 1.0 / unknown 0.4 / no 0.1
Em   = verified LLM malicious_prob        (Engine / Host mode)
       GBM probability                    (no LLM, trained model available)
       0.7 x LLM + 0.3 x GBM              (both)
       rule-baseline probability          (neither)
E    = 1 - (1 - Ev)(1 - Em)               noisy-OR
Risk = 100 x A^0.5 x E^0.7 + hard rules
```

Levels: 0-15 benign, 16-35 low, 36-60 medium, 61-80 high, 81-100 critical.
Every exponent, weight and threshold is configurable (`[fuse]` in `config.toml`).

## Capability `A`

`A = min(1, max(single item weights) + 0.15 x number of combination bonuses)`.
Optional permissions count at half weight.

| Weight | Items |
|---|---|
| 1.0 critical | `debugger`, `proxy`, `nativeMessaging`; all-site host access combined with `cookies`, `scripting`, `webRequest` or `declarativeNetRequest`; MV2 all-site host access (enables `tabs.executeScript`) |
| 0.7 high | all/most-site host access alone; content scripts on all sites; `management`, `history`, `privacy`, `contentSettings`, `desktopCapture`, `tabCapture`, `browsingData`, `pageCapture`, `userScripts`...; DNR rules that modify headers; MV2 CSP with `unsafe-eval` or remote script sources |
| 0.4 medium | `tabs`, `webNavigation`, `downloads`, `clipboardRead`, `geolocation`, `identity`, `cookies`, `scripting`, `webRequest`, `bookmarks`...; specific-site host access; search/homepage/startup overrides; DNR redirects; sandbox `unsafe-eval` |
| 0.1 low | `storage`, `alarms`, `contextMenus`, `notifications`, `activeTab`, `sidePanel`, ...; `wasm-unsafe-eval` |

Combination bonuses (+0.15 each): content scripts in every frame of every site;
`externally_connectable` open to all sites; web-accessible resources open to all sites;
content scripts in the page's MAIN world on all sites; updates served outside the Web
Store; DNR rules that strip security headers; extension pages loading remote scripts.

## Vulnerability evidence `Ev`

Libraries are identified by retire.js (CLI or the built-in matcher over its repository).
EPSS percentiles come from FIRST; without EPSS the severity is used
(low 0.1, medium 0.25, high 0.45, critical 0.6). Reachability starts as `unknown`; the
investigator (or a Host-mode client) decides `yes` / `no` when the vulnerable library
functions appear in the extension's own code.

## Malicious evidence `Em`

* **Rule baseline** - noisy-OR of static signals: sensitive data flowing into a network
  sink, a network response driving code execution, prompt-injection attempts, proxy or
  debugger control, tampering with other extensions, search/header hijacking, remote code,
  heavy obfuscation near network code, time bombs, evasion checks.
* **GBM** - LightGBM on ~200 static features, trained with family-grouped cross-validation.
* **LLM** - `malicious_prob` of the investigator's verdict after verification.

## Hard rules and safeguards

* A **verified** malicious verdict with at least one verified evidence quote sets a floor of 80.
* If the verdict says the behaviour is consistent with the declared purpose **and** every
  host receiving data is first-party, `Em` is halved.
* **One-way rule**: the LLM can raise risk freely, but it can lower a high static prior
  (>= 0.4) only with a verified, purpose-consistent verdict that carries evidence.
* **Verifier**: quotes must exist (whitespace-insensitive) at the cited lines (+-2), or
  elsewhere in the same file for quotes of 20+ characters (lines are corrected); unmatched
  evidence is removed; a malicious verdict left without evidence becomes suspicious and is
  flagged for human review. A benign verdict for an extension with capability >= 0.8 and
  exfiltration code also needs purpose-consistency evidence, or it is flagged for review.

Every report shows `A`, `Ev`, `Em` (and its source), `E`, the raw formula value and any
hard rule that applied.
