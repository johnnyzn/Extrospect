"""AST source/sink rules (tree-sitter) + per-file call index and endpoint extraction.

Every finding is a :class:`~extrospect.models.Sink` with a ``kind`` (what), ``group``
(source / exfil / dynamic_code / hijack / suspicious / surface) and ``weight`` (danger
used for ranking and routing, not a verdict). Synthetic *pattern* sinks are added when a
function (or its direct callees) combines a sensitive source with an exfiltration
channel, or a network fetch with dynamic code execution.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from tree_sitter import Node, QueryCursor

from extrospect.models import ContextKind, Endpoint, Sink, SinkGroup
from extrospect.static.jsparse import (
    ParsedJs,
    call_args,
    column_of,
    compiled_query,
    end_line_of,
    is_literal,
    line_of,
    member_chain,
    node_text,
    normalize_api,
    object_keys,
    run_query,
    string_value,
)
from extrospect.util import host_of, one_line, registrable_domain, shannon_entropy


@dataclass(frozen=True)
class SinkRule:
    kind: str
    group: SinkGroup
    weight: float


def _r(kind: str, group: SinkGroup, weight: float) -> SinkRule:
    return SinkRule(kind, group, weight)


# --------------------------------------------------------------------------- rule tables

CALL_RULES: dict[str, SinkRule] = {
    # sensitive data sources
    "chrome.cookies.getAll": _r("cookie_read", "source", 0.7),
    "chrome.cookies.get": _r("cookie_read", "source", 0.6),
    "chrome.cookies.getAllCookieStores": _r("cookie_read", "source", 0.3),
    "chrome.cookies.onChanged.addListener": _r("cookie_read", "source", 0.6),
    "chrome.history.search": _r("history_read", "source", 0.7),
    "chrome.history.getVisits": _r("history_read", "source", 0.7),
    "chrome.history.onVisited.addListener": _r("history_read", "source", 0.6),
    "chrome.tabs.query": _r("tab_url_read", "source", 0.25),
    "chrome.tabs.get": _r("tab_url_read", "source", 0.25),
    "chrome.tabs.getCurrent": _r("tab_url_read", "source", 0.2),
    "chrome.tabs.onUpdated.addListener": _r("tab_activity", "source", 0.35),
    "chrome.tabs.onActivated.addListener": _r("tab_activity", "source", 0.3),
    "chrome.tabs.onCreated.addListener": _r("tab_activity", "source", 0.3),
    "chrome.bookmarks.getTree": _r("bookmarks_read", "source", 0.4),
    "chrome.bookmarks.getRecent": _r("bookmarks_read", "source", 0.4),
    "chrome.bookmarks.search": _r("bookmarks_read", "source", 0.4),
    "chrome.bookmarks.getSubTree": _r("bookmarks_read", "source", 0.4),
    "chrome.topSites.get": _r("topsites_read", "source", 0.4),
    "chrome.sessions.getRecentlyClosed": _r("sessions_read", "source", 0.4),
    "chrome.sessions.getDevices": _r("sessions_read", "source", 0.4),
    "chrome.identity.getAuthToken": _r("identity_read", "source", 0.5),
    "chrome.identity.getProfileUserInfo": _r("identity_read", "source", 0.5),
    "chrome.identity.launchWebAuthFlow": _r("identity_read", "source", 0.4),
    "chrome.identity.getAccounts": _r("identity_read", "source", 0.5),
    "chrome.tabs.captureVisibleTab": _r("screen_capture", "source", 0.6),
    "chrome.tabCapture.capture": _r("screen_capture", "source", 0.6),
    "chrome.tabCapture.getMediaStreamId": _r("screen_capture", "source", 0.6),
    "chrome.desktopCapture.chooseDesktopMedia": _r("screen_capture", "source", 0.6),
    "chrome.pageCapture.saveAsMHTML": _r("screen_capture", "source", 0.6),
    "navigator.clipboard.readText": _r("clipboard_read", "source", 0.5),
    "navigator.clipboard.read": _r("clipboard_read", "source", 0.5),
    "chrome.management.getAll": _r("extension_inventory", "source", 0.4),
    "navigator.geolocation.getCurrentPosition": _r("geolocation_read", "source", 0.4),
    "navigator.geolocation.watchPosition": _r("geolocation_read", "source", 0.4),
    "chrome.downloads.search": _r("downloads_read", "source", 0.3),
    "localStorage.getItem": _r("storage_read", "source", 0.15),
    "sessionStorage.getItem": _r("storage_read", "source", 0.15),
    "chrome.webRequest.onAuthRequired.addListener": _r("credential_intercept", "source", 0.7),
    # exfiltration channels
    "fetch": _r("network_exfil", "exfil", 0.35),
    "navigator.sendBeacon": _r("network_exfil", "exfil", 0.6),
    "$.ajax": _r("network_exfil", "exfil", 0.4),
    "$.post": _r("network_exfil", "exfil", 0.45),
    "$.get": _r("network_exfil", "exfil", 0.35),
    "$.getJSON": _r("network_exfil", "exfil", 0.35),
    "jQuery.ajax": _r("network_exfil", "exfil", 0.4),
    "jQuery.post": _r("network_exfil", "exfil", 0.45),
    "jQuery.get": _r("network_exfil", "exfil", 0.35),
    "axios": _r("network_exfil", "exfil", 0.4),
    "axios.get": _r("network_exfil", "exfil", 0.35),
    "axios.post": _r("network_exfil", "exfil", 0.45),
    "axios.put": _r("network_exfil", "exfil", 0.45),
    "axios.request": _r("network_exfil", "exfil", 0.4),
    "chrome.runtime.sendNativeMessage": _r("native_messaging", "exfil", 0.8),
    "chrome.runtime.connectNative": _r("native_messaging", "exfil", 0.8),
    "chrome.runtime.setUninstallURL": _r("uninstall_beacon", "exfil", 0.15),
    # dynamic code
    "eval": _r("dynamic_code", "dynamic_code", 0.85),
    "Function": _r("dynamic_code", "dynamic_code", 0.85),
    "chrome.scripting.executeScript": _r("script_injection", "dynamic_code", 0.5),
    "chrome.tabs.executeScript": _r("script_injection", "dynamic_code", 0.45),
    "chrome.scripting.registerContentScripts": _r("script_injection", "dynamic_code", 0.5),
    "chrome.scripting.updateContentScripts": _r("script_injection", "dynamic_code", 0.5),
    "chrome.userScripts.register": _r("script_injection", "dynamic_code", 0.6),
    "chrome.userScripts.update": _r("script_injection", "dynamic_code", 0.6),
    "chrome.userScripts.execute": _r("script_injection", "dynamic_code", 0.6),
    "WebAssembly.instantiate": _r("wasm_exec", "dynamic_code", 0.4),
    "WebAssembly.instantiateStreaming": _r("wasm_exec", "dynamic_code", 0.45),
    "WebAssembly.compile": _r("wasm_exec", "dynamic_code", 0.4),
    "WebAssembly.compileStreaming": _r("wasm_exec", "dynamic_code", 0.45),
    # hijack / tamper
    "chrome.declarativeNetRequest.updateDynamicRules": _r("request_rewrite", "hijack", 0.6),
    "chrome.declarativeNetRequest.updateSessionRules": _r("request_rewrite", "hijack", 0.55),
    "chrome.proxy.settings.set": _r("proxy_hijack", "hijack", 0.9),
    "chrome.debugger.attach": _r("debugger_control", "hijack", 0.9),
    "chrome.debugger.sendCommand": _r("debugger_control", "hijack", 0.85),
    "chrome.management.setEnabled": _r("extension_tamper", "hijack", 0.7),
    "chrome.management.uninstall": _r("extension_tamper", "hijack", 0.7),
    "chrome.search.query": _r("search_hijack", "hijack", 0.3),
    "chrome.browsingData.remove": _r("data_wipe", "hijack", 0.5),
    "chrome.history.deleteUrl": _r("history_tamper", "hijack", 0.5),
    "chrome.history.deleteAll": _r("history_tamper", "hijack", 0.5),
    "chrome.history.deleteRange": _r("history_tamper", "hijack", 0.5),
    "chrome.downloads.download": _r("file_download", "hijack", 0.35),
    "chrome.cookies.set": _r("cookie_tamper", "hijack", 0.55),
    "chrome.cookies.remove": _r("cookie_tamper", "hijack", 0.45),
    "location.replace": _r("navigation_hijack", "hijack", 0.3),
    "location.assign": _r("navigation_hijack", "hijack", 0.3),
    "document.location.replace": _r("navigation_hijack", "hijack", 0.3),
    "document.location.assign": _r("navigation_hijack", "hijack", 0.3),
    "open": _r("popup_open", "hijack", 0.15),
    "chrome.tabs.create": _r("tab_open", "hijack", 0.15),
    "chrome.windows.create": _r("tab_open", "hijack", 0.15),
    # externally reachable surface
    "chrome.runtime.onMessageExternal.addListener": _r("external_message_surface", "surface", 0.4),
    "chrome.runtime.onConnectExternal.addListener": _r("external_message_surface", "surface", 0.4),
}

# Prefix + suffix rules: (prefix, suffix, rule).
AFFIX_RULES: list[tuple[str, str, SinkRule]] = [
    ("chrome.webRequest.on", ".addListener", _r("web_request_observe", "source", 0.5)),
    ("chrome.webNavigation.on", ".addListener", _r("navigation_tracking", "source", 0.45)),
    ("chrome.privacy.", ".set", _r("privacy_settings_change", "hijack", 0.6)),
    ("chrome.contentSettings.", ".set", _r("content_settings_change", "hijack", 0.5)),
    ("chrome.browsingData.remove", "", _r("data_wipe", "hijack", 0.5)),
]

SENSITIVE_SOURCES = {
    "cookie_read",
    "history_read",
    "header_read",
    "password_field_read",
    "payment_field_read",
    "keystroke_capture",
    "form_capture",
    "page_content_read",
    "clipboard_read",
    "screen_capture",
    "identity_read",
    "bookmarks_read",
    "credential_intercept",
    "navigation_tracking",
    "tab_activity",
    "web_request_observe",
    "page_storage_read",
    "sessions_read",
    "topsites_read",
}
EXFIL_KINDS = {"network_exfil", "native_messaging"}
CONTROL_KINDS = {
    "dynamic_code",
    "script_injection",
    "request_rewrite",
    "html_injection",
    "remote_code",
}

_PASSWORD_RE = re.compile(r"password|passwd|pwd|type\s*=\s*['\"]?password", re.I)
_PAYMENT_RE = re.compile(r"cc-?num|card-?number|cardnumber|cvv|cvc|cc-?exp|credit.?card", re.I)
_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_EXT_ID_RE = re.compile(r"^[a-p]{32}$")
_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\^`{|}]+")
_IGNORED_HOSTS = {
    "www.w3.org",
    "w3.org",
    "schemas.xmlsoap.org",
    "schema.org",
    "json-schema.org",
    "ns.adobe.com",
    "purl.org",
    "xmlns.com",
    "example.com",
    "example.org",
    "example.net",
    "www.example.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "a",
    "b",
}
_OBF_IDENT_RE = re.compile(r"\b_0x[0-9a-f]{3,}\b")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{80,}={0,2}$")
_IP_URL_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class ObfuscationStats:
    obf_identifiers: int = 0
    hex_escapes: int = 0
    atob_calls: int = 0
    char_code_calls: int = 0
    base64_strings: int = 0
    long_strings: int = 0
    max_string_len: int = 0
    avg_identifier_len: float = 0.0
    string_entropy: float = 0.0
    score: float = 0.0


@dataclass
class FileScan:
    rel: str
    context: ContextKind
    sinks: list[Sink] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    chrome_apis: Counter[str] = field(default_factory=Counter)
    # function index (-1 = top level) -> short names of functions it calls
    calls_by_function: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    # short callee name -> [(line, enclosing function index or -1)]
    call_sites: dict[str, list[tuple[int, int]]] = field(default_factory=lambda: defaultdict(list))
    obfuscation: ObfuscationStats = field(default_factory=ObfuscationStats)
    parse_error: bool = False
    lines: int = 0
    bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel": self.rel,
            "context": self.context,
            "sinks": [s.model_dump(mode="json") for s in self.sinks],
            "endpoints": [e.model_dump(mode="json") for e in self.endpoints],
            "chrome_apis": dict(self.chrome_apis),
            "calls_by_function": {str(k): sorted(v) for k, v in self.calls_by_function.items()},
            "call_sites": {k: [list(x) for x in v] for k, v in self.call_sites.items()},
            "obfuscation": asdict(self.obfuscation),
            "parse_error": self.parse_error,
            "lines": self.lines,
            "bytes": self.bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], rel: str | None = None) -> FileScan:
        scan = cls(rel=rel or data["rel"], context=data.get("context", "unknown"))
        scan.sinks = [Sink.model_validate({**s, "file": scan.rel}) for s in data.get("sinks", [])]
        scan.endpoints = [
            Endpoint.model_validate({**e, "file": scan.rel}) for e in data.get("endpoints", [])
        ]
        scan.chrome_apis = Counter(data.get("chrome_apis", {}))
        scan.calls_by_function = defaultdict(
            set, {int(k): set(v) for k, v in data.get("calls_by_function", {}).items()}
        )
        scan.call_sites = defaultdict(
            list,
            {k: [(int(a), int(b)) for a, b in v] for k, v in data.get("call_sites", {}).items()},
        )
        scan.obfuscation = ObfuscationStats(**data.get("obfuscation", {}))
        scan.parse_error = bool(data.get("parse_error", False))
        scan.lines = int(data.get("lines", 0))
        scan.bytes = int(data.get("bytes", 0))
        return scan


class _Scanner:
    def __init__(self, parsed: ParsedJs, context: ContextKind) -> None:
        self.p = parsed
        self.scan = FileScan(rel=parsed.rel, context=context, parse_error=parsed.has_error)
        self.scan.lines = len(parsed.lines)
        self.scan.bytes = len(parsed.text.encode("utf-8", "surrogatepass"))
        self.aliases = parsed.aliases
        self.script_vars: set[str] = set()
        self.image_vars: set[str] = set()
        self.frame_vars: set[str] = set()
        self.has_xhr = "XMLHttpRequest" in parsed.text
        # id(sink) -> (enclosing function index or -1, start byte, end byte)
        self.sink_fn: dict[int, tuple[int, int, int]] = {}

    # -------------------------------------------------------------- helpers

    def _snippet(self, node: Node) -> str:
        line = self.p.line_text(line_of(node))
        if len(line) <= 220:
            return line.strip()
        col = column_of(node)
        start = max(0, col - 60)
        return ("…" if start else "") + line[start : start + 200].strip() + "…"

    def _fn_index(self, node: Node) -> int:
        fn = self.p.innermost_function(node.start_byte)
        return fn.index if fn else -1

    def add(
        self,
        node: Node,
        rule: SinkRule,
        api: str,
        weight: float | None = None,
        detail: str | None = None,
    ) -> None:
        fn = self.p.innermost_function(node.start_byte)
        sink = Sink(
            kind=rule.kind,
            group=rule.group,
            api=api,
            file=self.p.rel,
            line=line_of(node),
            column=column_of(node),
            end_line=end_line_of(node),
            snippet=self._snippet(node),
            weight=round(min(1.0, weight if weight is not None else rule.weight), 3),
            function=fn.display if fn else None,
            detail=detail,
        )
        self.scan.sinks.append(sink)
        self.sink_fn[id(sink)] = (fn.index if fn else -1, node.start_byte, node.end_byte)

    # -------------------------------------------------------------- var typing

    def _collect_element_vars(self) -> None:
        query = "(variable_declarator name: (identifier) @name value: (_) @value)\n(assignment_expression left: (identifier) @name right: (_) @value)"
        for _, match in QueryCursor(compiled_query(query)).matches(self.p.root):
            if not match.get("name") or not match.get("value"):
                continue
            name, value = match["name"][0], match["value"][0]
            text = node_text(value)
            if not text:
                continue
            low = text[:200].lower()
            if "createelement" in low:
                if "'script'" in low or '"script"' in low or "`script`" in low:
                    self.script_vars.add(node_text(name))
                elif "'img'" in low or '"img"' in low:
                    self.image_vars.add(node_text(name))
                elif "'iframe'" in low or '"iframe"' in low:
                    self.frame_vars.add(node_text(name))
            elif low.startswith("new image"):
                self.image_vars.add(node_text(name))

    # -------------------------------------------------------------- calls

    def _rule_for(self, api: str) -> SinkRule | None:
        rule = CALL_RULES.get(api)
        if rule:
            return rule
        for prefix, suffix, affix_rule in AFFIX_RULES:
            if api.startswith(prefix) and api.endswith(suffix) and len(api) > len(prefix):
                return affix_rule
        return None

    def visit_call(self, node: Node) -> None:
        callee = node.child_by_field_name("function")
        chain = member_chain(callee, self.aliases)
        api = normalize_api(chain)
        if not api:
            return
        args = call_args(node)
        short = api.rsplit(".", 1)[-1]
        fn_idx = self._fn_index(node)
        if short and short.isidentifier():
            self.scan.calls_by_function[fn_idx].add(short)
            self.scan.call_sites[short].append((line_of(node), fn_idx))
        if api.startswith("chrome."):
            self.scan.chrome_apis[api] += 1

        rule = self._rule_for(api)
        if rule is not None:
            self._apply_call_rule(node, api, rule, args)
            return
        self._special_calls(node, api, short, args)

    def _apply_call_rule(self, node: Node, api: str, rule: SinkRule, args: list[Node]) -> None:
        first = args[0] if args else None
        weight = rule.weight
        detail: str | None = None
        if (
            api == "chrome.cookies.getAll"
            and first is not None
            and first.type == "object"
            and not first.named_child_count
        ):
            weight, detail = 0.8, "empty filter: every cookie of every site"
        elif api in {"eval", "Function"}:
            if args and all(is_literal(a) for a in args):
                weight, detail = 0.3, "literal argument"
        elif api == "fetch":
            options = object_keys(args[1]) if len(args) > 1 else {}
            method = options.get("method")
            method_value = (string_value(method) or "").upper() if method is not None else ""
            if "body" in options or method_value in {"POST", "PUT", "PATCH"}:
                weight, detail = 0.5, "sends a request body"
            if first is not None and not is_literal(first):
                weight += 0.05
        elif api == "chrome.scripting.executeScript":
            keys = object_keys(first)
            if "func" in keys or "function" in keys:
                weight, detail = 0.55, "injects a function"
            elif "files" in keys:
                weight, detail = 0.4, "injects packaged files"
            world = keys.get("world")
            if world is not None and (string_value(world) or "").upper() == "MAIN":
                weight += 0.1
                detail = (detail + "; " if detail else "") + "MAIN world"
        elif api == "chrome.tabs.executeScript":
            keys = object_keys(args[1] if len(args) > 1 and args[0].type != "object" else first)
            if "code" in keys:
                code_value = keys["code"]
                weight = 0.6 if is_literal(code_value) else 0.75
                detail = "injects a code string"
        elif api.startswith("chrome.webRequest.on") and api.endswith(".addListener"):
            extra = " ".join(node_text(a) for a in args[1:])
            if "blocking" in extra:
                self.add(
                    node, _r("request_intercept", "hijack", 0.6), api, detail="blocking listener"
                )
            if "requestHeaders" in extra or "extraHeaders" in extra:
                self.add(
                    node, _r("header_read", "source", 0.6), api, detail="reads request headers"
                )
        elif api == "chrome.runtime.setUninstallURL" and first is not None and is_literal(first):
            weight = 0.1
        elif api == "open":
            # bare open(...) is window.open after normalisation
            pass
        elif api in {"chrome.tabs.create", "chrome.windows.create"}:
            keys = object_keys(first)
            if "url" not in keys:
                return
        self.add(node, rule, api, weight=weight, detail=detail)

    def _special_calls(self, node: Node, api: str, short: str, args: list[Node]) -> None:
        first = args[0] if args else None
        first_str = string_value(first, unescape=True) if first is not None else None
        if short in {"setTimeout", "setInterval"} and api in {"setTimeout", "setInterval"}:
            if first is not None and (
                first.type in {"string", "template_string"}
                or (
                    first.type == "binary_expression"
                    and ("'" in node_text(first) or '"' in node_text(first))
                )
            ):
                self.add(
                    node,
                    _r("dynamic_code", "dynamic_code", 0.7),
                    api,
                    detail="string evaluated as code",
                )
            return
        if api == "importScripts":
            for arg in args:
                value = string_value(arg, unescape=True)
                if value is None or value.startswith(("http://", "https://", "//")):
                    self.add(
                        node,
                        _r("remote_code", "dynamic_code", 0.8),
                        api,
                        detail="loads remote or dynamic script",
                    )
                    break
            return
        if api.endswith(".constructor") and api.count("constructor") >= 2 and args:
            self.add(
                node,
                _r("dynamic_code", "dynamic_code", 0.8),
                api,
                detail="Function constructor via prototype chain",
            )
            return
        if short == "createElement" and first_str is not None:
            tag = first_str.lower()
            if tag == "script":
                self.add(
                    node,
                    _r("script_element", "dynamic_code", 0.4),
                    "document.createElement('script')",
                )
            elif tag == "iframe":
                self.add(
                    node,
                    _r("frame_injection", "dynamic_code", 0.2),
                    "document.createElement('iframe')",
                )
            return
        if (
            api in {"document.write", "document.writeln"}
            and first is not None
            and not is_literal(first)
        ):
            self.add(node, _r("html_injection", "dynamic_code", 0.5), api)
            return
        if short == "insertAdjacentHTML" and len(args) > 1 and not is_literal(args[1]):
            self.add(node, _r("html_injection", "dynamic_code", 0.35), "Element.insertAdjacentHTML")
            return
        if (
            short == "open"
            and self.has_xhr
            and first_str is not None
            and first_str.upper() in _HTTP_METHODS
        ):
            self.add(
                node,
                _r("network_exfil", "exfil", 0.4),
                "XMLHttpRequest.open",
                detail=f"{first_str.upper()} request",
            )
            return
        if short == "execCommand" and first_str and first_str.lower() == "paste":
            self.add(node, _r("clipboard_read", "source", 0.5), "document.execCommand('paste')")
            return
        if (
            short
            in {
                "querySelector",
                "querySelectorAll",
                "getElementsByName",
                "getElementById",
                "getElementsByClassName",
            }
            and first_str
        ):
            if _PASSWORD_RE.search(first_str):
                self.add(
                    node,
                    _r("password_field_read", "source", 0.7),
                    f"document.{short}",
                    detail=first_str[:80],
                )
            elif _PAYMENT_RE.search(first_str):
                self.add(
                    node,
                    _r("payment_field_read", "source", 0.7),
                    f"document.{short}",
                    detail=first_str[:80],
                )
            return
        if short == "addEventListener" and first_str:
            event = first_str.lower()
            if event in {"keydown", "keypress", "keyup", "input"}:
                self.add(
                    node, _r("keystroke_capture", "source", 0.45), f"addEventListener('{event}')"
                )
            elif event == "submit":
                self.add(node, _r("form_capture", "source", 0.5), "addEventListener('submit')")
            elif event in {"copy", "paste", "cut"}:
                self.add(node, _r("clipboard_event", "source", 0.3), f"addEventListener('{event}')")
            elif event == "message" and api.split(".")[0] in {"addEventListener", "window", "self"}:
                self.add(
                    node,
                    _r("postmessage_listener", "surface", 0.2),
                    "window.addEventListener('message')",
                )
            return
        if short == "setAttribute" and len(args) > 1 and first_str and not is_literal(args[1]):
            attr = first_str.lower()
            if attr == "href":
                self.add(node, _r("link_rewrite", "hijack", 0.3), "Element.setAttribute('href')")
            elif attr == "src":
                self.add(
                    node,
                    _r("resource_injection", "dynamic_code", 0.25),
                    "Element.setAttribute('src')",
                )
            return
        if api == "String.fromCharCode" and len(args) >= 8:
            self.add(
                node,
                _r("char_code_decode", "suspicious", 0.3),
                api,
                detail=f"{len(args)} char codes",
            )
            return
        if (
            api in {"chrome.runtime.sendMessage", "chrome.runtime.connect"}
            and first_str
            and _EXT_ID_RE.match(first_str)
        ):
            self.add(node, _r("cross_extension_message", "exfil", 0.3), api, detail=first_str)
            return
        if api == "chrome.tabs.update" and len(args) >= 1:
            keys = object_keys(args[-1] if args[-1].type == "object" else first)
            if "url" in keys:
                self.add(node, _r("navigation_hijack", "hijack", 0.3), api)
            return

    def visit_new(self, node: Node) -> None:
        ctor = normalize_api(member_chain(node.child_by_field_name("constructor"), self.aliases))
        if not ctor:
            return
        args = call_args(node)
        if ctor == "Function":
            weight = 0.3 if args and all(is_literal(a) for a in args) else 0.85
            self.add(node, _r("dynamic_code", "dynamic_code", weight), "new Function")
        elif ctor == "WebSocket":
            self.add(node, _r("network_exfil", "exfil", 0.5), "new WebSocket")
        elif ctor == "EventSource":
            self.add(node, _r("remote_channel", "exfil", 0.3), "new EventSource")
        elif ctor in {"Worker", "SharedWorker"} and args and not is_literal(args[0]):
            self.add(
                node,
                _r("dynamic_code", "dynamic_code", 0.5),
                f"new {ctor}",
                detail="dynamic worker source",
            )

    # -------------------------------------------------------------- assignments

    def visit_assignment(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type not in {
            "member_expression",
            "subscript_expression",
            "identifier",
        }:
            return
        chain = normalize_api(member_chain(left, None)) or ""
        literal_rhs = is_literal(right)
        prop = chain.rsplit(".", 1)[-1] if "." in chain else chain
        obj_node = left.child_by_field_name("object") if left.type != "identifier" else None
        obj_name = (
            node_text(obj_node) if obj_node is not None and obj_node.type == "identifier" else ""
        )
        obj_is_new_image = (
            obj_node is not None
            and obj_node.type == "new_expression"
            and "Image" in node_text(obj_node)[:12]
        )

        if chain in {
            "location",
            "location.href",
            "document.location",
            "document.location.href",
            "document.URL",
        }:
            self.add(
                node, _r("navigation_hijack", "hijack", 0.3 if literal_rhs else 0.4), f"{chain} ="
            )
        elif chain == "document.cookie":
            self.add(node, _r("cookie_write", "hijack", 0.2), "document.cookie =")
        elif prop in {"innerHTML", "outerHTML"} and not literal_rhs:
            if obj_name in self.script_vars:
                self.add(node, _r("script_injection", "dynamic_code", 0.6), f"<script>.{prop} =")
            else:
                self.add(node, _r("html_injection", "dynamic_code", 0.35), f"Element.{prop} =")
        elif (
            prop in {"textContent", "text", "innerText"}
            and obj_name in self.script_vars
            and not literal_rhs
        ):
            self.add(
                node,
                _r("script_injection", "dynamic_code", 0.6),
                f"<script>.{prop} =",
                detail="inline script injected into the page",
            )
        elif prop == "src" and not literal_rhs:
            if obj_name in self.script_vars:
                self.add(
                    node,
                    _r("script_injection", "dynamic_code", 0.6),
                    "<script>.src =",
                    detail="dynamic script source",
                )
            elif obj_name in self.image_vars or obj_is_new_image:
                self.add(
                    node, _r("network_exfil", "exfil", 0.5), "Image.src =", detail="pixel request"
                )
            elif obj_name in self.frame_vars:
                self.add(node, _r("frame_injection", "dynamic_code", 0.3), "<iframe>.src =")
        elif prop == "src" and literal_rhs and obj_name in self.script_vars:
            value = string_value(right, unescape=True) or ""
            if value.startswith(("http://", "https://", "//")):
                self.add(
                    node,
                    _r("script_injection", "dynamic_code", 0.55),
                    "<script>.src =",
                    detail="remote script",
                )
        elif prop == "href" and chain not in {"location.href"} and not literal_rhs:
            self.add(node, _r("link_rewrite", "hijack", 0.3), "Element.href =")

    # -------------------------------------------------------------- member reads

    def visit_member(self, node: Node) -> None:
        parent = node.parent
        if (
            parent is not None
            and parent.type
            in {
                "assignment_expression",
                "augmented_assignment_expression",
            }
            and parent.child_by_field_name("left") == node
        ):
            return
        if (
            parent is not None
            and parent.type == "member_expression"
            and parent.child_by_field_name("object") == node
        ):
            return  # only the outermost member expression is interesting
        if (
            parent is not None
            and parent.type == "call_expression"
            and parent.child_by_field_name("function") == node
        ):
            return
        chain = normalize_api(member_chain(node, self.aliases)) or ""
        if chain == "document.cookie":
            self.add(node, _r("cookie_read", "source", 0.6), "document.cookie")
        elif chain in {
            "document.body.innerHTML",
            "document.body.outerHTML",
            "document.body.innerText",
            "document.body.textContent",
            "document.documentElement.outerHTML",
            "document.documentElement.innerHTML",
            "document.documentElement.innerText",
        }:
            self.add(node, _r("page_content_read", "source", 0.3), chain)
        elif chain.endswith(".installType") or chain == "navigator.webdriver":
            self.add(node, _r("evasion_check", "suspicious", 0.3), chain)

    # -------------------------------------------------------------- strings / misc

    def visit_strings(self, nodes: list[Node]) -> None:
        stats = self.scan.obfuscation
        entropy_total, entropy_count = 0.0, 0
        for node in nodes:
            value = string_value(node, unescape=True)
            if value is None:
                continue
            length = len(value)
            stats.max_string_len = max(stats.max_string_len, length)
            if length > 200:
                stats.long_strings += 1
            if length >= 80 and _BASE64_RE.match(value):
                stats.base64_strings += 1
            if 8 <= length <= 2000:
                entropy_total += shannon_entropy(value)
                entropy_count += 1
            if "://" in value and length < 2048:
                for url in _URL_RE.findall(value):
                    self._add_endpoint(url.rstrip(".,;)"), node)
        stats.string_entropy = entropy_total / entropy_count if entropy_count else 0.0

    def _add_endpoint(self, url: str, node: Node) -> None:
        host = host_of(url)
        if not host or host in _IGNORED_HOSTS or "${" in url or "%s" in host:
            return
        if "." not in host and not host.startswith("["):
            return  # "https://www\\.example" in a regex, single-label hosts, ...
        if len(self.scan.endpoints) >= 500:
            return
        category = "ip" if _IP_URL_RE.match(host) else None
        self.scan.endpoints.append(
            Endpoint(
                url=url[:300],
                host=host,
                registrable_domain=registrable_domain(host),
                file=self.p.rel,
                line=line_of(node),
                category=category,
            )
        )

    def visit_time_bombs(self, nodes: list[Node]) -> None:
        found = 0
        for node in nodes:
            text = node_text(node)
            if len(text) > 400 or ("Date" not in text and "getTime" not in text):
                continue
            numbers = re.findall(r"\b\d{8,}\b|\b\d+e\d+\b", text)
            big = False
            for raw in numbers:
                try:
                    value = float(raw)
                except ValueError:
                    continue
                if value >= 86_400_000:
                    big = True
            if big and re.search(r"Date\.now\(\)|new Date|getTime\(\)", text):
                self.add(
                    node,
                    _r("time_bomb", "suspicious", 0.5),
                    "Date comparison",
                    detail=one_line(text, 100),
                )
                found += 1
                if found >= 5:
                    break

    def finish_obfuscation(self, string_nodes: int) -> None:
        stats = self.scan.obfuscation
        text = self.p.text
        stats.obf_identifiers = len(_OBF_IDENT_RE.findall(text))
        stats.hex_escapes = len(_HEX_ESCAPE_RE.findall(text))
        stats.atob_calls = text.count("atob(")
        stats.char_code_calls = text.count("fromCharCode")
        idents = re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", text[:400_000])
        stats.avg_identifier_len = sum(map(len, idents)) / len(idents) if idents else 0.0
        kb = max(1.0, self.scan.bytes / 1024)
        score = 0.0
        score += min(0.45, stats.obf_identifiers / kb * 0.15)
        score += min(0.25, stats.hex_escapes / kb * 0.02)
        score += min(0.15, (stats.atob_calls + stats.char_code_calls) / kb * 0.1)
        score += min(0.15, stats.base64_strings * 0.03)
        if stats.string_entropy > 5.0:
            score += 0.1
        stats.score = round(min(1.0, score), 3)
        if stats.score >= 0.35:
            line = 1
            match = _OBF_IDENT_RE.search(text) or _HEX_ESCAPE_RE.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
            self.scan.sinks.append(
                Sink(
                    kind="obfuscation",
                    group="suspicious",
                    api="obfuscated code",
                    file=self.p.rel,
                    line=line,
                    snippet=one_line(self.p.line_text(line), 200),
                    weight=round(min(0.7, 0.3 + stats.score * 0.4), 3),
                    detail=(
                        f"_0x identifiers={stats.obf_identifiers}, \\x escapes={stats.hex_escapes}, "
                        f"atob/fromCharCode={stats.atob_calls + stats.char_code_calls}, base64 blobs={stats.base64_strings}"
                    ),
                )
            )


_QUERY = """
(call_expression) @call
(new_expression) @new
(assignment_expression) @assign
(augmented_assignment_expression) @assign
(member_expression) @member
(string) @string
(template_string) @string
(binary_expression) @binary
(debugger_statement) @debugger
"""


def scan_file(parsed: ParsedJs, context: ContextKind = "unknown") -> FileScan:
    """Run every sink rule over one parsed file."""
    scanner = _Scanner(parsed, context)
    scanner._collect_element_vars()
    captures = run_query(_QUERY, parsed.root)
    for node in captures.get("call", []):
        scanner.visit_call(node)
    for node in captures.get("new", []):
        scanner.visit_new(node)
    for node in captures.get("assign", []):
        scanner.visit_assignment(node)
    for node in captures.get("member", []):
        prop = node.child_by_field_name("property")
        if prop is not None and node_text(prop) in {
            "cookie",
            "innerHTML",
            "outerHTML",
            "innerText",
            "textContent",
            "installType",
            "webdriver",
        }:
            scanner.visit_member(node)
    strings = captures.get("string", [])
    scanner.visit_strings(strings)
    scanner.visit_time_bombs(captures.get("binary", []))
    debuggers = captures.get("debugger", [])
    if debuggers:
        scanner.add(
            debuggers[0],
            _r("anti_debug", "suspicious", 0.3),
            "debugger statement",
            detail=f"{len(debuggers)} statement(s)",
        )
    scanner.finish_obfuscation(len(strings))
    _adjust_for_context(scanner.scan)
    _add_patterns(scanner.scan, parsed, scanner.sink_fn)
    scanner.scan.sinks.sort(key=lambda s: (s.line, s.column, -s.weight))
    return scanner.scan


def _adjust_for_context(scan: FileScan) -> None:
    for sink in scan.sinks:
        if sink.kind == "storage_read" and scan.context == "content_script":
            sink.kind, sink.weight = "page_storage_read", 0.3
        if scan.context == "content_script" and sink.kind in {
            "keystroke_capture",
            "form_capture",
            "password_field_read",
        }:
            sink.weight = round(min(1.0, sink.weight + 0.1), 3)


class _Groups:
    """Union-find over function indexes (-1 = top-level code)."""

    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _flow_groups(
    scan: FileScan, parsed: ParsedJs, sink_meta: dict[int, tuple[int, int, int]]
) -> _Groups:
    """Group functions that belong to the same data flow.

    * a small nested function joins its parent (closures / inner callbacks);
    * a callback passed to a sink call joins the caller (``getAll({}, cb)``);
    * a function joins the same-file functions it calls by name.
    """
    groups = _Groups()
    for fn in parsed.functions:
        groups.find(fn.index)
        if fn.parent is not None:
            parent = parsed.function_by_index(fn.parent)
            if parent is not None and parent.lines <= 400:
                groups.union(fn.index, parent.index)
    for sink in scan.sinks:
        meta = sink_meta.get(id(sink))
        if meta is None:
            continue
        fn_index, start, end = meta
        for fn in parsed.functions:
            if start <= fn.start_byte and fn.end_byte <= end:
                groups.union(fn.index, fn_index)
    by_name: dict[str, list[int]] = defaultdict(list)
    for fn in parsed.functions:
        if fn.name:
            by_name[fn.name].append(fn.index)
    for fn_index, names in scan.calls_by_function.items():
        if fn_index < 0:
            continue  # top-level code calls everything; merging it would join unrelated flows
        for name in names:
            for target in by_name.get(name, [])[:5]:
                groups.union(fn_index, target)
    return groups


def _add_patterns(
    scan: FileScan, parsed: ParsedJs, sink_meta: dict[int, tuple[int, int, int]]
) -> None:
    """Synthetic sinks for source->exfil flows and fetch->eval style remote control."""
    groups = _flow_groups(scan, parsed, sink_meta)
    by_group: dict[int, list[Sink]] = defaultdict(list)
    for sink in scan.sinks:
        meta = sink_meta.get(id(sink))
        fn_index = meta[0] if meta else -1
        by_group[groups.find(fn_index)].append(sink)

    for group_sinks in by_group.values():
        sources = [s for s in group_sinks if s.kind in SENSITIVE_SOURCES]
        exfils = [s for s in group_sinks if s.kind in EXFIL_KINDS]
        controls = [s for s in group_sinks if s.kind in CONTROL_KINDS]
        networks = [s for s in group_sinks if s.kind in {"network_exfil", "remote_channel"}]
        if sources and exfils:
            src = max(sources, key=lambda s: s.weight)
            dst = max(exfils, key=lambda s: s.weight)
            scan.sinks.append(
                Sink(
                    kind="exfiltration_pattern",
                    group="suspicious",
                    api=f"{src.api} -> {dst.api}",
                    file=scan.rel,
                    line=dst.line,
                    column=dst.column,
                    snippet=dst.snippet,
                    weight=0.8 if src.weight >= 0.5 else 0.6,
                    function=dst.function,
                    detail=f"{src.kind} (line {src.line}) flows near {dst.kind} (line {dst.line})",
                )
            )
        if networks and controls:
            ctl = max(controls, key=lambda s: s.weight)
            net = networks[0]
            scan.sinks.append(
                Sink(
                    kind="remote_control_pattern",
                    group="suspicious",
                    api=f"{net.api} -> {ctl.api}",
                    file=scan.rel,
                    line=ctl.line,
                    column=ctl.column,
                    snippet=ctl.snippet,
                    weight=0.75,
                    function=ctl.function,
                    detail=f"network response (line {net.line}) near {ctl.kind} (line {ctl.line})",
                )
            )


def sink_counts(sinks: list[Sink]) -> dict[str, int]:
    counter = Counter(s.kind for s in sinks)
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


__all__ = [
    "AFFIX_RULES",
    "CALL_RULES",
    "CONTROL_KINDS",
    "EXFIL_KINDS",
    "SENSITIVE_SOURCES",
    "FileScan",
    "ObfuscationStats",
    "SinkRule",
    "scan_file",
    "sink_counts",
]
