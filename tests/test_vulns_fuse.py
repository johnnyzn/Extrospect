from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from extrospect.cache import Cache
from extrospect.config import FuseConfig
from extrospect.fuse import FuseInputs, fuse, level_for, vuln_evidence
from extrospect.http import HttpClient
from extrospect.models import CapabilityProfile, Evidence, Verdict, VulnFinding
from extrospect.static.vulns import (
    RetireMatcher,
    clean_version,
    fetch_epss,
    is_at_or_above,
    is_vulnerable,
    scan_with_python,
)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.9.0", "1.9.0", True),
        ("1.9.1", "1.9.0", True),
        ("1.8.9", "1.9.0", False),
        ("1.9.0b1", "1.9.0", False),
        ("1.9.0", "1.9.0b1", True),
        ("3.5", "3.5.0", True),
        ("10.0.0", "9.9.9", True),
        ("1.12.4", "1.12.0", True),
    ],
)
def test_retire_version_ordering(a: str, b: str, expected: bool) -> None:
    assert is_at_or_above(a, b) is expected


def test_vulnerability_ranges() -> None:
    vuln = {"atOrAbove": "1.4.0", "below": "1.12.0"}
    assert is_vulnerable("1.8.1", vuln)
    assert not is_vulnerable("1.3.2", vuln)
    assert not is_vulnerable("1.12.0", vuln)
    assert clean_version("1.8.1.min") == "1.8.1"


def test_python_matcher_on_fixture(fixtures_dir: Path, retire_repo: dict) -> None:
    scan = scan_with_python(fixtures_dir / "benign_legacy_jquery", retire_repo, 5_000_000)
    assert scan.libraries == {"js/jquery-1.8.1.min.js": ("jquery", "1.8.1")}
    assert {f.cve for f in scan.findings} == {"CVE-2012-6708", "CVE-2015-9251", "CVE-2020-11023"}
    assert all(f.reachable == "unknown" for f in scan.findings)


def test_matcher_content_extractor_without_filename(retire_repo: dict) -> None:
    matcher = RetireMatcher(retire_repo)
    text = "/** @license\n * lodash 4.17.15 <https://lodash.com/> */\nvar x;"
    assert matcher.identify("vendor/utils.js", text, "0" * 40) == ("lodash", "4.17.15")
    assert [v["identifiers"]["CVE"] for v in matcher.vulnerabilities("lodash", "4.17.15")] == [
        ["CVE-2021-23337"]
    ]


def test_epss_fetch_and_cache(settings) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "data": [
                    {
                        "cve": "CVE-2020-11023",
                        "epss": "0.0201",
                        "percentile": "0.8812",
                        "date": "2026-10-20",
                    }
                ],
            },
        )

    settings.network.offline = False
    http = HttpClient(settings.network, transport=httpx.MockTransport(handler))
    cache = Cache(None)
    scores = fetch_epss(["CVE-2020-11023", "CVE-2012-6708", "not-a-cve"], http, cache)
    assert scores == {"CVE-2020-11023": (0.0201, 0.8812)}
    # Second call is served from cache (including the known-missing CVE).
    assert fetch_epss(["CVE-2020-11023", "CVE-2012-6708"], http, cache) == scores
    assert len(calls) == 1


# --------------------------------------------------------------------------- fusion


def cap(score: float) -> CapabilityProfile:
    return CapabilityProfile(score=score)


def verdict(**kwargs) -> Verdict:
    base = {"label": "malicious", "malicious_prob": 0.9, "source": "engine"}
    base.update(kwargs)
    return Verdict(**base)


def test_formula_matches_roadmap() -> None:
    cfg = FuseConfig()
    score, level, b = fuse(FuseInputs(capability=cap(0.81), vulns=[], rules_prob=0.5), cfg)
    expected = 100 * (0.81**0.5) * (0.5**0.7)
    assert score == round(expected) and b.em_source == "rules"
    assert level == level_for(score, cfg)


def test_levels() -> None:
    cfg = FuseConfig()
    assert [level_for(x, cfg) for x in (0, 15, 16, 35, 36, 60, 61, 80, 81, 100)] == [
        "benign",
        "benign",
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
        "critical",
    ]


def test_vuln_evidence_uses_epss_and_reachability() -> None:
    cfg = FuseConfig()
    finding = VulnFinding(
        library="jquery", version="1.8.1", cve="CVE-1", epss_percentile=0.9, severity="medium"
    )
    assert vuln_evidence([finding], cfg) == pytest.approx(0.9 * 0.4)
    finding.reachable = "yes"
    assert vuln_evidence([finding], cfg) == pytest.approx(0.9)
    no_epss = VulnFinding(library="x", version="1", cve="CVE-2", severity="high")
    assert vuln_evidence([no_epss], cfg) == pytest.approx(0.45 * 0.4)


def test_noisy_or_and_llm_gbm_mix() -> None:
    cfg = FuseConfig()
    v = verdict(label="suspicious", malicious_prob=0.5, verified=True)
    _, _, b = fuse(FuseInputs(capability=cap(1.0), vulns=[], verdict=v, gbm_prob=0.2), cfg)
    assert b.Em == pytest.approx(0.7 * 0.5 + 0.3 * 0.2)
    finding = VulnFinding(library="x", version="1", cve="C", epss_percentile=0.5, reachable="yes")
    _, _, b2 = fuse(FuseInputs(capability=cap(1.0), vulns=[finding], verdict=v), cfg)
    assert pytest.approx(1 - (1 - 0.5) * (1 - 0.5)) == b2.E


def test_verified_malicious_floor() -> None:
    cfg = FuseConfig()
    ev = Evidence(claim="c", file="a.js", lines=(1, 1), quote="x", verified=True)
    v = verdict(malicious_prob=0.2, verified=True, evidence=[ev])
    score, level, b = fuse(FuseInputs(capability=cap(0.2), vulns=[]), cfg)
    assert score < 80
    score, level, b = fuse(FuseInputs(capability=cap(0.2), vulns=[], verdict=v), cfg)
    assert score == 80 and "verified_malicious_floor" in b.hard_rules and level == "high"
    unverified = verdict(malicious_prob=0.2, verified=False, evidence=[ev])
    score, _, _ = fuse(FuseInputs(capability=cap(0.2), vulns=[], verdict=unverified), cfg)
    assert score < 80


def test_one_way_rule_and_first_party_discount() -> None:
    cfg = FuseConfig()
    # LLM says benign, static prior is high, no verified purpose evidence -> keep the prior.
    lazy = verdict(label="benign", malicious_prob=0.05)
    _, _, b = fuse(FuseInputs(capability=cap(1.0), vulns=[], verdict=lazy, rules_prob=0.65), cfg)
    assert b.one_way_kept_static and b.Em == pytest.approx(0.65)
    # With verified, purpose-consistent evidence the LLM may lower it.
    ev = Evidence(
        claim="sends text to its own API",
        file="sw.js",
        lines=(9, 9),
        quote="fetch(API",
        verified=True,
    )
    good = verdict(
        label="benign", malicious_prob=0.05, verified=True, purpose_consistent=True, evidence=[ev]
    )
    _, _, b = fuse(FuseInputs(capability=cap(1.0), vulns=[], verdict=good, rules_prob=0.65), cfg)
    assert not b.one_way_kept_static and b.Em == pytest.approx(0.05)
    # First-party discount halves Em.
    _, _, b = fuse(
        FuseInputs(
            capability=cap(1.0), vulns=[], verdict=good, rules_prob=0.65, exfil_all_first_party=True
        ),
        cfg,
    )
    assert b.first_party_discount and b.Em == pytest.approx(0.025)
    # A low prior can always be lowered further.
    _, _, b = fuse(FuseInputs(capability=cap(1.0), vulns=[], verdict=lazy, rules_prob=0.1), cfg)
    assert not b.one_way_kept_static and b.Em == pytest.approx(0.05)
