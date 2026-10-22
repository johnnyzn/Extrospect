"""Numeric features per extension for the gradient-boosting baseline (roadmap M2).

Feature order is fixed by :data:`FEATURE_NAMES`; adding a feature means retraining.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import TYPE_CHECKING

from extrospect.static.permissions import PERMISSION_TIERS
from extrospect.static.surface import breadth_of

if TYPE_CHECKING:
    from extrospect.static.analyzer import StaticResult

TRACKED_PERMISSIONS = sorted(PERMISSION_TIERS)
SINK_KINDS = [
    "cookie_read",
    "history_read",
    "tab_url_read",
    "tab_activity",
    "navigation_tracking",
    "web_request_observe",
    "header_read",
    "request_intercept",
    "credential_intercept",
    "bookmarks_read",
    "identity_read",
    "screen_capture",
    "clipboard_read",
    "password_field_read",
    "payment_field_read",
    "keystroke_capture",
    "form_capture",
    "page_content_read",
    "page_storage_read",
    "network_exfil",
    "native_messaging",
    "remote_channel",
    "cross_extension_message",
    "dynamic_code",
    "remote_code",
    "script_injection",
    "script_element",
    "html_injection",
    "wasm_exec",
    "request_rewrite",
    "proxy_hijack",
    "debugger_control",
    "extension_tamper",
    "privacy_settings_change",
    "search_hijack",
    "navigation_hijack",
    "link_rewrite",
    "data_wipe",
    "history_tamper",
    "cookie_tamper",
    "external_message_surface",
    "obfuscation",
    "char_code_decode",
    "time_bomb",
    "anti_debug",
    "evasion_check",
    "exfiltration_pattern",
    "remote_control_pattern",
    "prompt_injection",
]
GROUPS = ["source", "exfil", "dynamic_code", "hijack", "suspicious", "surface"]

FEATURE_NAMES: list[str] = (
    [f"perm:{p}" for p in TRACKED_PERMISSIONS]
    + [
        f"optperm:{p}"
        for p in (
            "debugger",
            "proxy",
            "nativeMessaging",
            "cookies",
            "history",
            "management",
            "scripting",
            "webRequest",
        )
    ]
    + [f"sink:{k}" for k in SINK_KINDS]
    + [f"group:{g}" for g in GROUPS]
    + [
        "capability_score",
        "capability_max_item",
        "capability_combos",
        "broad_host",
        "host_all",
        "host_count",
        "optional_broad_host",
        "manifest_version",
        "cs_count",
        "cs_all_sites",
        "cs_all_frames",
        "cs_main_world",
        "cs_document_start",
        "war_open_all",
        "ext_connectable_broad",
        "offstore_update",
        "csp_unsafe_eval",
        "csp_remote",
        "override_search",
        "override_newtab",
        "dnr_rules",
        "dnr_modify_headers",
        "dnr_strip_security",
        "background_service_worker",
        "js_files",
        "log_total_bytes",
        "log_analyzed_bytes",
        "stripped_ratio",
        "minified_files",
        "deobfuscated_files",
        "wasm_files",
        "obfuscation_score",
        "log_endpoints",
        "distinct_hosts",
        "ip_endpoints",
        "third_party_hosts",
        "vulns",
        "max_epss",
        "libraries",
        "injection_attempts",
        "max_sink_weight",
        "mean_top5_weight",
        "slices",
        "max_slice_danger",
        "chrome_api_namespaces",
        "remote_script_tags",
        "inline_scripts",
    ]
)


def extract_features(static: StaticResult) -> dict[str, float]:
    m = static.manifest
    surface = static.surface
    cap = static.capability
    features: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)
    perms = set(m.permissions)
    for perm in TRACKED_PERMISSIONS:
        features[f"perm:{perm}"] = 1.0 if perm in perms else 0.0
    for perm in (
        "debugger",
        "proxy",
        "nativeMessaging",
        "cookies",
        "history",
        "management",
        "scripting",
        "webRequest",
    ):
        features[f"optperm:{perm}"] = 1.0 if perm in m.optional_permissions else 0.0
    kinds = Counter(s.kind for s in static.sinks)
    groups: Counter[str] = Counter(s.group for s in static.sinks)
    for kind in SINK_KINDS:
        features[f"sink:{kind}"] = float(kinds.get(kind, 0))
    for group in GROUPS:
        features[f"group:{group}"] = float(groups.get(group, 0))
    flags = set(cap.flags)
    hosts = {e.host for e in static.endpoints}
    weights = sorted((s.weight for s in static.sinks), reverse=True)
    stats = static.stats
    features.update(
        {
            "capability_score": cap.score,
            "capability_max_item": cap.max_item,
            "capability_combos": float(cap.combo_count),
            "broad_host": float(cap.broad_host),
            "host_all": float(breadth_of(m.host_permissions) == "all"),
            "host_count": float(len(m.host_permissions)),
            "optional_broad_host": float(
                breadth_of(m.optional_host_permissions) in {"all", "broad"}
            ),
            "manifest_version": float(m.manifest_version),
            "cs_count": float(len(surface.content_scripts)),
            "cs_all_sites": float(surface.cs_all_sites),
            "cs_all_frames": float(surface.cs_all_frames_all_sites),
            "cs_main_world": float(surface.cs_main_world_all_sites),
            "cs_document_start": float(surface.cs_document_start_all_sites),
            "war_open_all": float(surface.war_open_all),
            "ext_connectable_broad": float(surface.ext_connectable_broad),
            "offstore_update": float(surface.offstore_update_url),
            "csp_unsafe_eval": float(
                "CSP_UNSAFE_EVAL" in flags or "CSP_SANDBOX_UNSAFE_EVAL" in flags
            ),
            "csp_remote": float(
                "CSP_REMOTE_SCRIPT" in flags or "CSP_SANDBOX_REMOTE_SCRIPT" in flags
            ),
            "override_search": float("search_url" in surface.overrides),
            "override_newtab": float("url_newtab" in surface.overrides),
            "dnr_rules": float(surface.dnr.rules),
            "dnr_modify_headers": float(surface.dnr.modify_headers),
            "dnr_strip_security": float(bool(surface.dnr.removed_security_headers)),
            "background_service_worker": float(surface.background_type == "service_worker"),
            "js_files": float(stats.js_files),
            "log_total_bytes": math.log1p(stats.total_bytes),
            "log_analyzed_bytes": math.log1p(stats.analyzed_bytes),
            "stripped_ratio": stats.stripped_files / stats.js_files if stats.js_files else 0.0,
            "minified_files": float(stats.minified_files),
            "deobfuscated_files": float(stats.deobfuscated_files),
            "wasm_files": float(stats.wasm_files),
            "obfuscation_score": stats.obfuscation_score,
            "log_endpoints": math.log1p(len(static.endpoints)),
            "distinct_hosts": float(len(hosts)),
            "ip_endpoints": float(sum(1 for e in static.endpoints if e.category == "ip")),
            "third_party_hosts": float(
                len({e.host for e in static.endpoints if e.first_party is False})
            ),
            "vulns": float(len(static.vulns)),
            "max_epss": max((v.epss_percentile or 0.0 for v in static.vulns), default=0.0),
            "libraries": float(len(static.libraries)),
            "injection_attempts": float(len(static.injections)),
            "max_sink_weight": weights[0] if weights else 0.0,
            "mean_top5_weight": sum(weights[:5]) / 5.0,
            "slices": float(len(static.slices)),
            "max_slice_danger": max((s.danger for s in static.slices), default=0.0),
            "chrome_api_namespaces": float(
                len({api.split(".")[1] for api in static.chrome_apis if api.count(".") >= 1})
            ),
            "remote_script_tags": float(len(surface.remote_script_tags)),
            "inline_scripts": float(sum(surface.inline_scripts.values())),
        }
    )
    return features


def feature_vector(static: StaticResult) -> list[float]:
    features = extract_features(static)
    return [float(features[name]) for name in FEATURE_NAMES]


__all__ = ["FEATURE_NAMES", "extract_features", "feature_vector"]
