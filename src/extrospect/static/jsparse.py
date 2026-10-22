"""tree-sitter wrapper: parsing, callee normalisation and a per-file function index.

Line numbers are 1-based and computed from ``\\n`` only (tree-sitter rows). Never use
``str.splitlines()`` on source text: it also splits on ``\\u2028``, form feeds, etc.,
which would desynchronise line numbers from the parser and the Verifier.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from functools import cache
from typing import Any

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Node, Parser, Query, QueryCursor, Tree

GLOBAL_PREFIXES = ("window.", "self.", "globalThis.", "global.", "top.", "parent.")
FUNCTION_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
}
_ESCAPE_RE = re.compile(
    r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|\r?\n|.)", re.S
)
_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


@cache
def js_language() -> Language:
    return Language(tsjs.language())


def new_parser() -> Parser:
    return Parser(js_language())


@cache
def compiled_query(source: str) -> Query:
    return Query(js_language(), source)


def run_query(source: str, node: Node) -> dict[str, list[Node]]:
    return QueryCursor(compiled_query(source)).captures(node)


def split_lines(text: str) -> list[str]:
    """Split like tree-sitter rows (``\\n`` only) and drop a trailing ``\\r``."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def node_text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


# Bind Point objects to a local before reading fields: py-tree-sitter 0.26.0 frees a
# temporary Point before ``node.end_point.row`` is read (garbage values / segfaults).


def line_of(node: Node) -> int:
    point = node.start_point
    return int(point[0]) + 1


def end_line_of(node: Node) -> int:
    point = node.end_point
    return int(point[0]) + 1


def column_of(node: Node) -> int:
    point = node.start_point
    return int(point[1])


def js_unescape(raw: str) -> str:
    """Decode JS string escapes (``\\x41``, ``\\u0041``, ``\\u{1F600}``, octal, ``\\n`` ...)."""
    if "\\" not in raw:
        return raw

    def repl(match: re.Match[str]) -> str:
        esc = match.group(1)
        if esc.startswith("u{"):
            try:
                return chr(int(esc[2:-1], 16))
            except (ValueError, OverflowError):
                return esc
        if esc[0] == "u" and len(esc) == 5:
            return chr(int(esc[1:], 16))
        if esc[0] == "x" and len(esc) == 3:
            return chr(int(esc[1:], 16))
        if esc in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[esc]
        if esc[0] in "01234567":
            return chr(int(esc, 8))
        if esc in {"\n", "\r\n"}:
            return ""  # line continuation
        return esc

    return _ESCAPE_RE.sub(repl, raw)


def string_value(node: Node | None, unescape: bool = False) -> str | None:
    """Value of a string literal / substitution-free template string, else ``None``."""
    if node is None:
        return None
    if node.type == "string":
        raw = node_text(node)
        value = raw[1:-1] if len(raw) >= 2 else ""
        return js_unescape(value) if unescape else value
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.named_children):
            return None
        raw = node_text(node)
        value = raw[1:-1] if len(raw) >= 2 else ""
        return js_unescape(value) if unescape else value
    return None


def _strip_parens(node: Node) -> Node:
    while node.type == "parenthesized_expression" and node.named_child_count:
        inner = node.named_children[0]
        node = inner
    if node.type == "sequence_expression" and node.named_child_count:
        # (0, foo.bar)(...) - webpack/babel indirect call idiom.
        node = node.named_children[-1]
    return node


def member_chain(node: Node | None, aliases: dict[str, str] | None = None) -> str | None:
    """Flatten ``a.b["c"].d`` into ``a.b.c.d``. Unknown computed parts become ``[?]``."""
    if node is None:
        return None
    node = _strip_parens(node)
    if node.type == "identifier":
        name = node_text(node)
        if aliases and name in aliases:
            return aliases[name]
        return name
    if node.type in {"this", "super"}:
        return node.type
    if node.type == "member_expression":
        obj = member_chain(node.child_by_field_name("object"), aliases)
        prop = node.child_by_field_name("property")
        prop_text = node_text(prop) if prop is not None else "?"
        if obj is None:
            return f"?.{prop_text}"
        return f"{obj}.{prop_text}"
    if node.type == "subscript_expression":
        obj = member_chain(node.child_by_field_name("object"), aliases)
        index = node.child_by_field_name("index")
        value = string_value(index)
        part = (
            value
            if value is not None and value.replace("_", "").replace("$", "").isalnum()
            else "[?]"
        )
        if obj is None:
            return f"?.{part}"
        return f"{obj}.{part}"
    if node.type == "call_expression":
        callee = member_chain(node.child_by_field_name("function"), aliases)
        return f"{callee}()" if callee else None
    if node.type == "new_expression":
        ctor = member_chain(node.child_by_field_name("constructor"), aliases)
        return f"new {ctor}" if ctor else None
    return None


def normalize_api(chain: str | None) -> str | None:
    """Canonical API name: strip ``window.``-style prefixes, ``browser.*`` -> ``chrome.*``."""
    if not chain:
        return chain
    changed = True
    while changed:
        changed = False
        for prefix in GLOBAL_PREFIXES:
            if chain.startswith(prefix):
                chain = chain[len(prefix) :]
                changed = True
    if chain == "browser" or chain.startswith("browser."):
        chain = "chrome" + chain[len("browser") :]
    return chain


@dataclass
class FunctionInfo:
    index: int
    name: str | None  # declared or inferred name usable for caller lookup
    display: str  # human readable, e.g. "sendData" or "callback of chrome.cookies.getAll"
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    parent: int | None = None

    @property
    def lines(self) -> int:
        return self.end_line - self.start_line + 1


def _infer_function_name(node: Node, aliases: dict[str, str]) -> tuple[str | None, str]:
    name_node = node.child_by_field_name("name")
    if name_node is not None and node.type != "method_definition":
        name = node_text(name_node)
        return name, name
    if node.type == "method_definition" and name_node is not None:
        name = node_text(name_node)
        return name, name
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    if parent is None:
        return None, "<anonymous>"
    if parent.type == "variable_declarator":
        target = parent.child_by_field_name("name")
        if target is not None and target.type == "identifier":
            name = node_text(target)
            return name, name
    if parent.type in {"assignment_expression", "augmented_assignment_expression"}:
        left = parent.child_by_field_name("left")
        chain = member_chain(left) if left is not None else None
        if chain:
            short = chain.rsplit(".", 1)[-1]
            return short, chain
    if parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key is not None:
            key_text = string_value(key) or node_text(key)
            return key_text, key_text
    if parent.type == "arguments":
        call = parent.parent
        if call is not None and call.type in {"call_expression", "new_expression"}:
            field_name = "function" if call.type == "call_expression" else "constructor"
            callee = normalize_api(member_chain(call.child_by_field_name(field_name), aliases))
            return None, f"callback of {callee or '?'}"
    return None, "<anonymous>"


@dataclass
class ParsedJs:
    """A parsed JS file plus indexes used by sink extraction and slicing."""

    rel: str
    text: str
    tree: Tree
    lines: list[str]
    functions: list[FunctionInfo] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    _starts: list[int] = field(default_factory=list)
    _line_starts: list[int] = field(default_factory=list)

    def offset_of(self, line: int, column: int = 0) -> int:
        """Byte offset of a 1-based line and a byte column (tree-sitter coordinates)."""
        if not self._line_starts:
            starts = [0]
            acc = 0
            for text_line in self.text.split("\n"):
                acc += len(text_line.encode("utf-8", "surrogatepass")) + 1
                starts.append(acc)
            self._line_starts = starts
        if line - 1 >= len(self._line_starts):
            return self._line_starts[-1]
        return self._line_starts[max(0, line - 1)] + max(0, column)

    def function_at(self, line: int, column: int = 0) -> FunctionInfo | None:
        return self.innermost_function(self.offset_of(line, column))

    _has_error: bool | None = None

    @property
    def root(self) -> Node:
        if self.tree is None:
            raise RuntimeError(f"syntax tree of {self.rel} was released")
        return self.tree.root_node

    @property
    def has_error(self) -> bool:
        if self._has_error is None:
            self._has_error = (
                bool(self.tree.root_node.has_error) if self.tree is not None else False
            )
        return self._has_error

    def release_tree(self) -> None:
        """Drop the tree-sitter tree (large) once scanning and sanitising are done."""
        _ = self.has_error
        self.tree = None  # type: ignore[assignment]

    def innermost_function(self, byte_offset: int) -> FunctionInfo | None:
        idx = bisect.bisect_right(self._starts, byte_offset) - 1
        while idx >= 0:
            fn = self.functions[idx]
            if fn.start_byte <= byte_offset < fn.end_byte:
                return fn
            idx -= 1
        return None

    def function_by_index(self, index: int | None) -> FunctionInfo | None:
        if index is None or index < 0 or index >= len(self.functions):
            return None
        return self.functions[index]

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""


_ALIAS_QUERY = "(variable_declarator name: (_) @name value: (_) @value)"
_FUNCTION_QUERY = "\n".join(f"({kind}) @fn" for kind in sorted(FUNCTION_TYPES))


MIN_ALIAS_LENGTH = 3
BUILTIN_ALIAS_TARGETS = {"fetch", "eval", "Function", "XMLHttpRequest", "WebSocket", "atob"}


def _collect_aliases(root: Node) -> dict[str, str]:
    """``const c = chrome.cookies`` / ``const api = browser || chrome`` / ``const {cookies} = chrome``.

    Aliases are scope-insensitive, so they are only trusted when unambiguous: the name is
    declared exactly once in the file and is not a minifier-style short identifier
    (``const t = Function`` in one scope must not turn every ``t(...)`` into ``Function``).
    """
    candidates: dict[str, str] = {}
    declared: dict[str, int] = {}
    for _, match in QueryCursor(compiled_query(_ALIAS_QUERY)).matches(root):
        if not match.get("name") or not match.get("value"):
            continue
        name_node = match["name"][0]
        value = _strip_parens(match["value"][0])
        if name_node.type == "identifier":
            name = node_text(name_node)
            declared[name] = declared.get(name, 0) + 1
            target = None
            if value.type in {"identifier", "member_expression", "subscript_expression"}:
                chain = normalize_api(member_chain(value)) or ""
                is_chrome = chain == "chrome" or chain.startswith("chrome.")
                if is_chrome or (chain in BUILTIN_ALIAS_TARGETS and len(name) >= 4):
                    target = chain
            elif value.type in {"binary_expression", "ternary_expression"}:
                text = node_text(value)
                if re.search(r"\b(chrome|browser)\b", text):
                    target = "chrome"
            if target:
                candidates[name] = target
        elif name_node.type == "object_pattern":
            base = normalize_api(member_chain(value))
            for child in name_node.named_children:
                alias_name, prop = None, None
                if child.type == "shorthand_property_identifier_pattern":
                    alias_name = prop = node_text(child)
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        alias_name, prop = node_text(val), node_text(key)
                if alias_name is None:
                    continue
                declared[alias_name] = declared.get(alias_name, 0) + 1
                if base and (base == "chrome" or base.startswith("chrome.")):
                    candidates[alias_name] = f"{base}.{prop}"
    return {
        name: target
        for name, target in candidates.items()
        if declared.get(name, 0) == 1 and len(name) >= MIN_ALIAS_LENGTH
    }


def parse_js(rel: str, text: str) -> ParsedJs:
    parser = new_parser()
    tree = parser.parse(text.encode("utf-8", "surrogatepass"))
    parsed = ParsedJs(rel=rel, text=text, tree=tree, lines=split_lines(text))
    parsed.aliases = _collect_aliases(tree.root_node)

    fn_nodes = sorted(
        run_query(_FUNCTION_QUERY, tree.root_node).get("fn", []), key=lambda n: n.start_byte
    )
    functions: list[FunctionInfo] = []
    stack: list[FunctionInfo] = []
    for node in fn_nodes:
        name, display = _infer_function_name(node, parsed.aliases)
        while stack and not (stack[-1].start_byte <= node.start_byte < stack[-1].end_byte):
            stack.pop()
        info = FunctionInfo(
            index=len(functions),
            name=name,
            display=display,
            start_line=line_of(node),
            end_line=end_line_of(node),
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            parent=stack[-1].index if stack else None,
        )
        functions.append(info)
        stack.append(info)
    parsed.functions = functions
    parsed._starts = [f.start_byte for f in functions]
    return parsed


def call_args(node: Node) -> list[Node]:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.named_children if c.type != "comment"]


def object_keys(node: Node | None) -> dict[str, Node]:
    """Map of literal keys -> value nodes for an object literal argument."""
    result: dict[str, Node] = {}
    if node is None or node.type != "object":
        return result
    for child in node.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is not None and value is not None:
                result[string_value(key) or node_text(key)] = value
        elif child.type == "shorthand_property_identifier":
            result[node_text(child)] = child
        elif child.type == "method_definition":
            name = child.child_by_field_name("name")
            if name is not None:
                result[node_text(name)] = child
    return result


def is_literal(node: Node | None) -> bool:
    if node is None:
        return False
    node = _strip_parens(node)
    if node.type in {"string", "number", "true", "false", "null", "undefined", "regex"}:
        return True
    return node.type == "template_string" and string_value(node) is not None


def describe(node: Node | None, limit: int = 80) -> str:
    from extrospect.util import one_line

    return one_line(node_text(node), limit)


__all__: list[Any] = [
    "FUNCTION_TYPES",
    "FunctionInfo",
    "ParsedJs",
    "call_args",
    "column_of",
    "describe",
    "end_line_of",
    "is_literal",
    "js_language",
    "js_unescape",
    "line_of",
    "member_chain",
    "new_parser",
    "node_text",
    "normalize_api",
    "object_keys",
    "parse_js",
    "run_query",
    "split_lines",
    "string_value",
]
