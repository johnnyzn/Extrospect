"""Permission tiers and combination rules -> capability profile ``A``.

Scoring rule (roadmap 1d): ``A = min(1, max(single item weights) + 0.15 * combo_count)``.
Optional permissions count at half weight. The tier table is the initial version and
is meant to be calibrated on the evaluation set; items marked "extension" go beyond
the roadmap's v1 table.
"""

from __future__ import annotations

from typing import Any

from extrospect.i18n import t
from extrospect.models import CapabilityFactor, CapabilityProfile, ManifestSummary
from extrospect.static.surface import AttackSurface, breadth_of, classify_host_pattern
from extrospect.util import host_of, registrable_domain

TIER_WEIGHTS: dict[str, float] = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
COMBO_BONUS = 0.15
OPTIONAL_FACTOR = 0.5
MANY_HOSTS_THRESHOLD = 30

PERMISSION_TIERS: dict[str, str] = {
    # critical
    "debugger": "critical",
    "proxy": "critical",
    "nativeMessaging": "critical",
    # high
    "management": "high",
    "history": "high",
    "privacy": "high",
    "contentSettings": "high",
    "desktopCapture": "high",
    "tabCapture": "high",
    # high (extension of the roadmap table)
    "browsingData": "high",
    "pageCapture": "high",
    "webAuthenticationProxy": "high",
    "certificateProvider": "high",
    "platformKeys": "high",
    "enterprise.platformKeys": "high",
    "vpnProvider": "high",
    "userScripts": "high",
    # medium
    "tabs": "medium",
    "webNavigation": "medium",
    "downloads": "medium",
    "clipboardRead": "medium",
    "geolocation": "medium",
    "identity": "medium",
    # medium (extension)
    "identity.email": "medium",
    "cookies": "medium",
    "scripting": "medium",
    "webRequest": "medium",
    "webRequestBlocking": "medium",
    "webRequestAuthProvider": "medium",
    "declarativeNetRequest": "medium",
    "declarativeNetRequestWithHostAccess": "medium",
    "declarativeNetRequestFeedback": "medium",
    "declarativeWebRequest": "medium",
    "bookmarks": "medium",
    "topSites": "medium",
    "sessions": "medium",
    "readingList": "medium",
    "search": "medium",
    "processes": "medium",
    "downloads.open": "medium",
    "fileSystemProvider": "medium",
    "documentScan": "medium",
    "signedInDevices": "medium",
    "dns": "medium",
    "audioCapture": "medium",
    "videoCapture": "medium",
    "accessibilityFeatures.read": "medium",
    "accessibilityFeatures.modify": "medium",
    "enterprise.deviceAttributes": "medium",
    "enterprise.hardwarePlatform": "medium",
    "enterprise.networkingAttributes": "medium",
    "experimental": "medium",
    # low
    "storage": "low",
    "alarms": "low",
    "contextMenus": "low",
    "notifications": "low",
    "activeTab": "low",
    "sidePanel": "low",
    # low (extension)
    "unlimitedStorage": "low",
    "offscreen": "low",
    "idle": "low",
    "power": "low",
    "tts": "low",
    "ttsEngine": "low",
    "fontSettings": "low",
    "gcm": "low",
    "background": "low",
    "clipboardWrite": "low",
    "declarativeContent": "low",
    "tabGroups": "low",
    "favicon": "low",
    "downloads.ui": "low",
    "downloads.shelf": "low",
    "system.cpu": "low",
    "system.memory": "low",
    "system.storage": "low",
    "system.display": "low",
    "wallpaper": "low",
    "printing": "low",
    "printingMetrics": "low",
    "printerProvider": "low",
    "loginState": "low",
    "contextMenus.override": "low",
    "webview": "low",
    "fileBrowserHandler": "low",
    "runtime": "low",
}

# Broad host access + any of these = critical (roadmap 1d).
SENSITIVE_WITH_BROAD_HOST: dict[str, str] = {
    "cookies": "cookies",
    "scripting": "scripting",
    "webRequest": "webRequest",
    "webRequestBlocking": "webRequest",
    "declarativeNetRequest": "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess": "declarativeNetRequest",
}


def permission_tier(permission: str) -> str | None:
    if permission in PERMISSION_TIERS:
        return PERMISSION_TIERS[permission]
    base = permission.split(".", 1)[0]
    return PERMISSION_TIERS.get(base)


def explain_factor(factor: CapabilityFactor, lang: str | None = None) -> str:
    params: dict[str, Any] = dict(factor.params)
    if "tier" in params:
        params["tier"] = t(f"tier.{params['tier']}", lang)
    text = t(f"cap.{factor.code}", lang, **params)
    if factor.optional:
        text += t("cap.optional_suffix", lang)
    return text


def _flag_for(factor: CapabilityFactor) -> str | None:
    if factor.code == "PERM":
        if factor.weight < 0.4:
            return None
        flag = f"PERM:{factor.params.get('permission')}"
    elif factor.code == "COMBO_BROAD_HOST_SENSITIVE":
        label = factor.params.get("flag") or factor.params.get("permission", "")
        flag = f"ALL_URLS+{str(label).upper()}"
    elif factor.code in {"HOST_SPECIFIC", "PERM_UNKNOWN", "OVERRIDE_NEWTAB"}:
        return None
    else:
        flag = factor.code
    return f"OPTIONAL:{flag}" if factor.optional else flag


def _host_factors(patterns: list[str], optional: bool) -> list[CapabilityFactor]:
    factors: list[CapabilityFactor] = []
    if not patterns:
        return factors
    scale = OPTIONAL_FACTOR if optional else 1.0
    broad = [p for p in patterns if classify_host_pattern(p) in {"all", "broad"}]
    if broad:
        factors.append(
            CapabilityFactor(
                code="HOST_BROAD",
                kind="host",
                weight=0.7 * scale,
                params={"pattern": broad[0]},
                optional=optional,
            )
        )
    if any(classify_host_pattern(p) == "file" for p in patterns):
        factors.append(
            CapabilityFactor(code="HOST_FILE", kind="host", weight=0.4 * scale, optional=optional)
        )
    specific = [p for p in patterns if classify_host_pattern(p) == "specific"]
    if specific:
        domains = {registrable_domain(host_of(p.replace("*.", ""))) for p in specific}
        domains.discard("")
        if len(domains) >= MANY_HOSTS_THRESHOLD:
            factors.append(
                CapabilityFactor(
                    code="HOST_MANY",
                    kind="host",
                    weight=0.7 * scale,
                    params={"count": len(domains)},
                    optional=optional,
                )
            )
        else:
            factors.append(
                CapabilityFactor(
                    code="HOST_SPECIFIC",
                    kind="host",
                    weight=0.4 * scale,
                    params={"count": len(specific), "examples": ", ".join(specific[:3])},
                    optional=optional,
                )
            )
    return factors


def compute_capability(
    manifest: ManifestSummary,
    surface: AttackSurface,
    csp_factors: list[CapabilityFactor],
    lang: str | None = None,
) -> CapabilityProfile:
    factors: list[CapabilityFactor] = []

    # ---- single permissions
    for optional, perms in ((False, manifest.permissions), (True, manifest.optional_permissions)):
        scale = OPTIONAL_FACTOR if optional else 1.0
        for perm in dict.fromkeys(perms):
            tier = permission_tier(perm)
            if tier is None:
                factors.append(
                    CapabilityFactor(
                        code="PERM_UNKNOWN",
                        kind="permission",
                        weight=0.1 * scale,
                        params={"permission": perm},
                        optional=optional,
                    )
                )
                continue
            factors.append(
                CapabilityFactor(
                    code="PERM",
                    kind="permission",
                    weight=TIER_WEIGHTS[tier] * scale,
                    params={"permission": perm, "tier": tier},
                    optional=optional,
                )
            )

    # ---- host access (explicit host permissions)
    factors.extend(_host_factors(manifest.host_permissions, optional=False))
    factors.extend(_host_factors(manifest.optional_host_permissions, optional=True))
    explicit_broad = breadth_of(manifest.host_permissions) in {"all", "broad"}
    optional_broad = breadth_of(manifest.optional_host_permissions) in {"all", "broad"}
    if surface.cs_all_sites:
        factors.append(CapabilityFactor(code="CS_ALL_SITES", kind="surface", weight=0.7))

    # ---- critical combination: broad host + sensitive API
    all_perms = set(manifest.permissions)
    optional_perms = set(manifest.optional_permissions)
    seen_combo: set[str] = set()
    for perm, label in SENSITIVE_WITH_BROAD_HOST.items():
        if label in seen_combo:
            continue
        if explicit_broad and perm in all_perms:
            factors.append(
                CapabilityFactor(
                    code="COMBO_BROAD_HOST_SENSITIVE",
                    kind="permission",
                    weight=1.0,
                    params={"permission": label},
                )
            )
            seen_combo.add(label)
        elif (explicit_broad or optional_broad) and (perm in all_perms or perm in optional_perms):
            factors.append(
                CapabilityFactor(
                    code="COMBO_BROAD_HOST_SENSITIVE",
                    kind="permission",
                    weight=1.0 * OPTIONAL_FACTOR,
                    params={"permission": label},
                    optional=True,
                )
            )
            seen_combo.add(label)
    if explicit_broad and manifest.manifest_version <= 2 and "scripting" not in seen_combo:
        # In MV2 any host permission enables chrome.tabs.executeScript on those hosts.
        factors.append(
            CapabilityFactor(
                code="COMBO_BROAD_HOST_SENSITIVE",
                kind="permission",
                weight=1.0,
                params={"permission": "tabs.executeScript (MV2)", "flag": "EXECUTESCRIPT_MV2"},
            )
        )

    # ---- declarativeNetRequest static rules
    dnr = surface.dnr
    if dnr.modify_headers:
        factors.append(CapabilityFactor(code="DNR_MODIFY_HEADERS", kind="surface", weight=0.7))
    if dnr.redirect:
        factors.append(CapabilityFactor(code="DNR_REDIRECT", kind="surface", weight=0.4))

    # ---- settings overrides
    overrides = surface.overrides
    if "search_url" in overrides:
        factors.append(
            CapabilityFactor(
                code="OVERRIDE_SEARCH",
                kind="override",
                weight=0.4,
                params={"search_url": overrides["search_url"]},
            )
        )
    if "homepage" in overrides:
        factors.append(
            CapabilityFactor(
                code="OVERRIDE_HOMEPAGE",
                kind="override",
                weight=0.4,
                params={"homepage": overrides["homepage"]},
            )
        )
    if "startup_pages" in overrides:
        factors.append(CapabilityFactor(code="OVERRIDE_STARTUP", kind="override", weight=0.4))
    if "url_newtab" in overrides:
        factors.append(CapabilityFactor(code="OVERRIDE_NEWTAB", kind="override", weight=0.1))
    if surface.ext_connectable_any_extension:
        factors.append(
            CapabilityFactor(code="EXT_CONNECTABLE_ANY_EXTENSION", kind="surface", weight=0.1)
        )

    # ---- CSP
    factors.extend(csp_factors)

    # ---- combination bonuses (+0.15 each)
    combos: list[CapabilityFactor] = []
    if surface.cs_all_frames_all_sites:
        combos.append(
            CapabilityFactor(code="COMBO_CS_ALL_FRAMES", kind="combo", weight=COMBO_BONUS)
        )
    if surface.ext_connectable_broad:
        combos.append(
            CapabilityFactor(
                code="COMBO_EXT_CONNECTABLE_BROAD",
                kind="combo",
                weight=COMBO_BONUS,
                params={"matches": ", ".join(surface.ext_connectable_matches[:3])},
            )
        )
    if surface.war_open_all:
        combos.append(CapabilityFactor(code="COMBO_WAR_ALL_URLS", kind="combo", weight=COMBO_BONUS))
    # extension of the roadmap table:
    if surface.cs_main_world_all_sites:
        combos.append(
            CapabilityFactor(code="COMBO_CS_MAIN_WORLD", kind="combo", weight=COMBO_BONUS)
        )
    if surface.offstore_update_url:
        combos.append(
            CapabilityFactor(
                code="COMBO_OFFSTORE_UPDATE",
                kind="combo",
                weight=COMBO_BONUS,
                params={"update_url": manifest.update_url or ""},
            )
        )
    if dnr.removed_security_headers:
        combos.append(
            CapabilityFactor(
                code="COMBO_DNR_STRIP_SECURITY",
                kind="combo",
                weight=COMBO_BONUS,
                params={"headers": ", ".join(dnr.removed_security_headers)},
            )
        )
    if surface.remote_script_tags:
        combos.append(
            CapabilityFactor(
                code="COMBO_REMOTE_SCRIPT_TAG",
                kind="combo",
                weight=COMBO_BONUS,
                params={"src": surface.remote_script_tags[0][1]},
            )
        )

    max_item = max((f.weight for f in factors), default=0.0)
    score = min(1.0, max_item + COMBO_BONUS * len(combos))
    all_factors = sorted(factors, key=lambda f: -f.weight) + combos
    flags = [flag for f in all_factors if (flag := _flag_for(f))]
    return CapabilityProfile(
        score=round(score, 4),
        flags=list(dict.fromkeys(flags)),
        explanation=[explain_factor(f, lang) for f in all_factors if f.weight >= 0.1],
        factors=all_factors,
        max_item=max_item,
        combo_count=len(combos),
        broad_host=explicit_broad or surface.cs_all_sites,
    )


__all__ = [
    "COMBO_BONUS",
    "PERMISSION_TIERS",
    "SENSITIVE_WITH_BROAD_HOST",
    "TIER_WEIGHTS",
    "compute_capability",
    "explain_factor",
    "permission_tier",
]
