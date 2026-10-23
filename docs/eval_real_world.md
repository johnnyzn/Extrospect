# Real-world evaluation (2026-10-23)

First evaluation on extensions downloaded from the Chrome Web Store, complementing the
fixture smoke test. Pipeline `0.1.0+p1`, decision threshold: score >= 61 (high or
critical) counts as "flagged".

## Samples

`eval/fetch_samples.py` on `eval/datasets/seed.jsonl` (210 ids):

| Subset | Ids | Downloadable | Notes |
|---|---|---|---|
| malicious | 164 | 56 | 55 from one cluster (`palant-2023-06-cluster`), 1 from `extension-games-cluster` |
| benign_hard | 23 | 23 | password managers, ad blockers, wallets, translators, AI sidebars, dev tools |
| benign | 23 | 20 | popular everyday extensions |

**Label caveat.** All malicious ids come from 2023 "potentially malicious" lists. The
store only serves the *current* version, so the 56 downloadable ones are the extensions
that survived three more years in the store; their current code may no longer contain
what got them listed. Recall measured on them is therefore unreliable. The benign labels
(well-known publishers) are reliable, so the false-positive rates below are the solid
numbers.

## Results

**Static pipeline** (`run_eval.py --configs rules`, zero tokens, all 99 samples): see
[eval_results.md](eval_results.md).

| Subset | n | Flagged by the static score |
|---|---|---|
| benign_hard | 23 | 16 (69.6%) |
| benign | 20 | 5 (25.0%) |
| malicious (noisy labels) | 56 | 24 (42.9%) |

AUC 0.470: on real extensions the static score does not separate the two classes. Its
rule signals fire at least as often on large legitimate extensions as on the listed ones
(`link_rewrite` 79% of benign vs 64% of listed, `time_bomb` 58% vs 30%,
`exfiltration_pattern` 35% vs 34%).

**Host mode** (`eval/run_host_eval.py`, Claude Sonnet 5.5 driving the MCP server through
Claude Code, one fresh session per extension): 59 samples (16 listed as malicious, all
43 benign) plus the 7 fixtures.

| Scores | n | Precision | Recall | FPR | Hard-benign FPR | AUC |
|---|---|---|---|---|---|---|
| static (quick_scan), same 59 | 59 | 25.0% | 43.8% | 48.8% | 69.6% | 0.475 |
| host (final verdict) | 59 | 100.0% | 6.2% | **0.0%** | **0.0%** | 0.971 |
| host, fixtures (4 malicious incl. prompt injection, 3 benign) | 7 | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |

- Every one of the 43 benign extensions ended benign or low (highest final score 34),
  including the twelve the static score rated 87-97 (1Password, Ghostery, Keeper,
  Stylus, Dashlane, Wappalyzer, Privacy Badger, Tampermonkey, Adobe Acrobat, AdBlock,
  Bitwarden, Adblock Plus).
- Of the 16 listed extensions, the final verdicts were 1 malicious, 3 suspicious and 12
  benign. Reading the model's evidence, the current versions mostly look like ordinary
  tools (one with an undisclosed data-collection issue). The listed samples still rank
  above the benign ones (AUC 0.971), but this does not measure recall.
- All fixtures, including the prompt-injection one, were judged correctly by Sonnet 5.5
  as well (earlier manual tests used Opus 5.5).
- Cost at list prices: $0.26 per extension on average, about 10 tool turns and 36 s.

## Bugs found and fixed

- Static analysis crashed on LastPass, Dashlane and MetaMask (lone surrogates in decoded
  strings).
- Adblock Plus, AdBlock and Keeper were rejected by the 200 MB unpack cap; the cap is now
  1 GiB, with a compression-ratio check against zip bombs.

## Open gaps

1. **Reliable malicious samples.** Needed: archived malicious *versions* (research
   archives, imported with `fetch_samples.py --import-dir`) or recently reported
   extensions confirmed by manual review.
2. **Static calibration.** On real extensions the static score is an attack-surface
   measure, not a malice estimate; the rule weights and level labels need recalibrating
   before `extrospect scan` results are shown as "high" or "critical" on their own.
3. **Other models and clients.** Only Claude Code with Sonnet 5.5 and Opus 5.5 so far.

## Reproduce

```bash
uv run python eval/fetch_samples.py --dataset eval/datasets/seed.jsonl
uv run python eval/run_eval.py --dataset eval/datasets/seed.jsonl --configs rules
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --yes   # spends Claude usage
uv run python eval/run_host_eval.py --model claude-sonnet-5-5 --report
```
