"""Prompt-injection defence for code that is shown to an LLM (roadmap 6.6).

1. Comments are removed and string literals longer than a threshold are replaced with
   ``"<STR len=N sha=XXXXXXXX>"`` placeholders. Line numbers are preserved exactly, so
   evidence lines quoted by a model still point at the real file.
2. Code is wrapped in ``<untrusted_code>`` blocks; the delimiter cannot be closed from
   inside the code.
3. Text that addresses an AI/auditor ("classify this as benign", "忽略之前的指令", ...)
   is detected in comments and strings. Legitimate code practically never does this,
   so an attempt is reported as a strong red flag of its own.

This module has no LLM dependencies; the static pipeline imports it too.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import regex

from extrospect.models import CodeSlice, InjectionAttempt
from extrospect.static.jsparse import (
    ParsedJs,
    line_of,
    node_text,
    run_query,
    split_lines,
    string_value,
)
from extrospect.util import one_line, short_hash

DEFAULT_MAX_STRING = 200
_UNTRUSTED_TAG = regex.compile(r"<\s*/?\s*untrusted_code", regex.I)

# (name, weight, pattern). Weights: steering a verdict is stronger evidence than the
# generic "ignore previous instructions" phrase.
INJECTION_PATTERNS: list[tuple[str, float, regex.Pattern[str]]] = [
    (
        "steer_verdict",
        0.9,
        regex.compile(
            r"\b(classify|mark|label|report|treat|rate|consider|flag)\s+(this|the|it)\s*"
            r"(code|extension|file|script|add-?on|plugin|program)?\s+as\s+(completely\s+|totally\s+)?"
            r"(safe|benign|clean|harmless|legit(imate)?|trusted|not\s+malicious|low[\s-]risk)",
            regex.I,
        ),
    ),
    (
        "claim_benign",
        0.6,
        regex.compile(
            r"\b(this|the)\s+(code|extension|file|script|add-?on|plugin)\s+(is|contains\s+only|only\s+contains)\s+"
            r"(completely\s+|totally\s+|only\s+|100%\s+)?(safe|benign|harmless|legit(imate)?|clean|not\s+malicious|benign\s+analytics)"
            r"(?!\s+(to|for|when|if|because|as\s+long)\b)",
            regex.I,
        ),
    ),
    (
        "address_ai_auditor",
        0.9,
        regex.compile(
            r"\b(note|message|instructions?|attention|hello|dear)\s+(to|for)\s+(the\s+|all\s+|any\s+)?"
            r"(ai|llm|gpt|claude|language\s+model|automated|auditors?|reviewers?|scanners?|analysts?|"
            r"security\s+(auditors?|reviewers?|analysts?|scanners?|tools?)|ai\s+(security\s+)?(auditors?|reviewers?|scanners?|analysts?))",
            regex.I,
        ),
    ),
    (
        "ignore_instructions",
        0.7,
        regex.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding|system)\s+"
            r"(instructions?|prompts?|rules|guidelines|directions)",
            regex.I,
        ),
    ),
    (
        "suppress_findings",
        0.8,
        regex.compile(
            r"\b(do\s+not|don'?t|never)\s+(report|flag|mention|analy[sz]e|escalate)\s+(any\s+)?"
            r"(issues?|findings?|problems?|vulnerabilit(y|ies)|malware|this\s+(code|file|extension))",
            regex.I,
        ),
    ),
    # Chinese
    (
        "zh_ignore_instructions",
        0.7,
        regex.compile(
            r"(忽略|无视|忘记|忽视)(之前|以上|前面|先前|上述|此前)的?(所有|全部)?(指令|指示|提示|规则|说明|要求)"
        ),
    ),
    (
        "zh_steer_verdict",
        0.9,
        regex.compile(r"(判定|标记|视为|认定|评为|归类|识别)为?(安全|良性|无害|正常|合法)"),
    ),
    (
        "zh_claim_benign",
        0.6,
        regex.compile(
            r"(这|此|该|本)(段|个|份)?(代码|扩展|插件|脚本|文件|程序)(是|为|只包含|仅包含)(完全|绝对)?(安全|良性|无害|合法)"
        ),
    ),
    (
        "zh_suppress_findings",
        0.8,
        regex.compile(r"(不要|请勿|无需)(报告|标记|上报|提及)(任何)?(问题|风险|漏洞|恶意)"),
    ),
    (
        "zh_address_ai",
        0.9,
        regex.compile(
            r"(致|给|写给)(AI|人工智能|大模型|语言模型|模型|安全)?(审计员|审核员|分析师|审查者|扫描器)"
        ),
    ),
    # Japanese / Korean / European languages
    (
        "ja_ignore_instructions",
        0.7,
        regex.compile(r"(以前|前|上記|これまで)の(指示|命令|プロンプト)を(無視|忘れ)"),
    ),
    (
        "ja_claim_benign",
        0.6,
        regex.compile(r"この(コード|拡張機能|スクリプト|ファイル)は(安全|無害|良性)"),
    ),
    (
        "ko_ignore_instructions",
        0.7,
        regex.compile(r"(이전|위의|앞의)\s*(지시|명령|지침)(을|를)?\s*무시"),
    ),
    (
        "es_ignore_instructions",
        0.7,
        regex.compile(
            r"\bignora(r)?\s+(todas\s+)?las\s+instrucciones\s+(anteriores|previas)", regex.I
        ),
    ),
    (
        "fr_ignore_instructions",
        0.7,
        regex.compile(
            r"\bignore(z|r)?\s+(toutes\s+)?les\s+instructions\s+(précédentes|antérieures)", regex.I
        ),
    ),
    (
        "de_ignore_instructions",
        0.7,
        regex.compile(
            r"\bignorier(e|en)?\s+(alle\s+)?(vorherigen|bisherigen)\s+anweisungen", regex.I
        ),
    ),
    (
        "ru_ignore_instructions",
        0.7,
        regex.compile(
            r"игнорир(уй|уйте|овать)\s+(все\s+)?(предыдущие|прошлые)\s+(инструкции|указания)",
            regex.I,
        ),
    ),
]


@dataclass
class SanitizedSource:
    text: str  # same line count as the input
    strings: dict[str, str] = field(default_factory=dict)  # short sha -> elided string value
    flagged: set[str] = field(default_factory=set)  # shas of strings that contain injection text
    injections: list[InjectionAttempt] = field(default_factory=list)
    comments_removed: int = 0
    strings_elided: int = 0

    @property
    def lines(self) -> list[str]:
        return split_lines(self.text)


def detect_injection(text: str) -> tuple[str, float] | None:
    """Return (pattern name, weight) of the strongest injection pattern in ``text``."""
    best: tuple[str, float] | None = None
    for name, weight, pattern in INJECTION_PATTERNS:
        if pattern.search(text, timeout=0.5) and (best is None or weight > best[1]):
            best = (name, weight)
    return best


def placeholder(value: str, flagged: bool = False) -> str:
    suffix = " flagged=prompt-injection" if flagged else ""
    return f"<STR len={len(value)} sha={short_hash(value, 8)}{suffix}>"


def sanitize_source(parsed: ParsedJs, max_string: int = DEFAULT_MAX_STRING) -> SanitizedSource:
    source = parsed.text.encode("utf-8", "surrogatepass")
    replacements: list[tuple[int, int, bytes]] = []
    result = SanitizedSource(text="")
    captures = run_query(
        "(comment) @c (html_comment) @c (string) @s (template_string) @s", parsed.root
    )

    for node in captures.get("c", []):
        text = node_text(node)
        hit = detect_injection(text)
        if hit:
            result.injections.append(
                InjectionAttempt(
                    file=parsed.rel, line=line_of(node), text=one_line(text, 240), pattern=hit[0]
                )
            )
        replacements.append((node.start_byte, node.end_byte, b"\n" * text.count("\n")))
        result.comments_removed += 1

    for node in captures.get("s", []):
        value = string_value(node, unescape=True)
        if value is None:
            continue
        flagged = False
        if len(value) >= 12:
            hit = detect_injection(value)
            if hit:
                flagged = True
                result.injections.append(
                    InjectionAttempt(
                        file=parsed.rel,
                        line=line_of(node),
                        text=one_line(value, 240),
                        pattern=hit[0],
                    )
                )
        if len(value) > max_string or flagged:
            # Flagged strings are hidden from the model whatever their length.
            raw = node_text(node)
            sha = short_hash(value, 8)
            result.strings[sha] = value
            if flagged:
                result.flagged.add(sha)
            replacement = f'"{placeholder(value, flagged)}"' + "\n" * raw.count("\n")
            replacements.append((node.start_byte, node.end_byte, replacement.encode("utf-8")))
            result.strings_elided += 1

    replacements.sort(key=lambda r: r[0])
    out = bytearray()
    cursor = 0
    for start, end, repl in replacements:
        if start < cursor:  # nested (e.g. comment inside a template) - keep the outer edit
            continue
        out += source[cursor:start]
        out += repl
        cursor = end
    out += source[cursor:]
    text = out.decode("utf-8", "replace")
    # Strip trailing whitespace left by removed comments (does not change line count).
    lines = [line.rstrip() for line in text.split("\n")]
    result.text = _UNTRUSTED_TAG.sub("<untrusted-code-tag", "\n".join(lines))
    return result


def injection_weight(attempt: InjectionAttempt) -> float:
    for name, weight, _ in INJECTION_PATTERNS:
        if name == attempt.pattern:
            return weight
    return 0.6


def escape_untrusted(text: str) -> str:
    return _UNTRUSTED_TAG.sub("<untrusted-code-tag", text)


def render_numbered(slice_: CodeSlice) -> str:
    """Code with a line-number gutter (``  12 | code``); marker lines get ``   … |``."""
    lines = slice_.code.split("\n")
    width = max((len(str(n)) for n in slice_.line_map if n), default=3)
    rendered = []
    for idx, line in enumerate(lines):
        number = slice_.line_map[idx] if idx < len(slice_.line_map) else 0
        gutter = str(number).rjust(width) if number else "…".rjust(width)
        rendered.append(f"{gutter} | {line}")
    return "\n".join(rendered)


def wrap_untrusted(slice_: CodeSlice) -> str:
    body = escape_untrusted(render_numbered(slice_))
    return (
        f'<untrusted_code id="{slice_.slice_id}" file="{slice_.file}" context="{slice_.context}" '
        f'lines="{slice_.start_line}-{slice_.end_line}">\n{body}\n</untrusted_code>'
    )


def wrap_untrusted_text(text: str, label: str) -> str:
    return f'<untrusted_code id="{label}">\n{escape_untrusted(text)}\n</untrusted_code>'


__all__ = [
    "DEFAULT_MAX_STRING",
    "INJECTION_PATTERNS",
    "SanitizedSource",
    "detect_injection",
    "escape_untrusted",
    "injection_weight",
    "placeholder",
    "render_numbered",
    "sanitize_source",
    "wrap_untrusted",
    "wrap_untrusted_text",
]
