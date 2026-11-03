import json
from pathlib import Path

from semaphore.alerts import Alerter, ImageAlert
from semaphore.config import Config
from semaphore.scan import Finding, exploit_class, parse_matches
from semaphore.store import State

# Trimmed real Grype 0.121 output: httpd:2.4.49 and python:3.8-slim-buster
RAW = (Path(__file__).parent / "grype_sample.json").read_text()
SAMPLE = json.loads(RAW)

# CVE-2023-50387 is "wont-fix" in the real sample; cleared here so it stays the high-EPSS DoS fixture
SAMPLE["matches"][1]["vulnerability"]["fix"]["state"] = ""
KEV, DOS, RCE_MEDIUM, PLAIN = (
    "CVE-2021-42013|httpd|2.4.49",
    "CVE-2023-50387|libsystemd0|241-7~deb10u9",
    "CVE-2023-5752|pip|23.0.1",
    "CVE-2021-39537|libncursesw6|6.1+20181013-2+deb10u3",
)
IMG = "sha256:abc"


def parse(cfg=Config()):
    return parse_matches(SAMPLE, cfg.min_rank, cfg.epss_threshold)


def test_parse_matches_tiers():
    found, counts = parse()

    assert counts == {"Critical": 1, "High": 2, "Medium": 2}

    # CVE-2022-4415 (Medium, nothing urgent) is dropped; CVE-2023-5752 (Medium, CWE-77) is kept as urgent
    assert set(found) == {KEV, DOS, PLAIN}
    assert (found[KEV].kev, found[KEV].tier) == (True, "urgent")
    assert (found[DOS].cls, found[DOS].tier) == ("DoS", "urgent")  # EPSS 0.9999
    assert (
        RCE_MEDIUM not in found
    )  # CWE-77 but needs privileges (PR:L): not RCE, so a plain Medium
    assert (found[PLAIN].cls, found[PLAIN].tier) == ("", "normal")


def test_wont_fix_dropped_unless_known_exploited():
    found, _ = parse_matches(json.loads(RAW), 0, 0.1)

    assert {f.id for f in found.values()} == {
        "CVE-2021-42013",
        "CVE-2021-39537",
        "CVE-2023-5752",
    }  # both libsystemd0 CVEs dropped

    kev_wont_fix = json.loads(RAW)
    kev_wont_fix["matches"][0]["vulnerability"]["fix"]["state"] = "wont-fix"

    assert KEV in parse_matches(kev_wont_fix, 0, 0.1)[0]

    assert DOS in parse_matches(json.loads(RAW), 0, 0.1, skip_wont_fix=False)[0]


def test_exploit_class_rce_needs_no_privileges():
    v = {"cwes": [{"cwe": "CWE-77"}]}

    assert exploit_class(v, []) == "RCE"  # no CVSS: trust the CWE
    assert (
        exploit_class(
            {
                **v,
                "cvss": [
                    {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H"}
                ],
            },
            [],
        )
        == ""
    )
    assert (
        exploit_class(
            {**v, "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
            [],
        )
        == "RCE"
    )


def test_epss_threshold_is_configurable():
    found, _ = parse(Config(epss_threshold=1.0))

    assert found[DOS].tier == "normal"


def test_exploit_class_dos_from_cvss_vector_only():
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}, []
        )
        == "DoS"
    )
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H"}]},
            [],
        )
        == "DoS"
    )
    assert (
        exploit_class(
            {"cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}, []
        )
        == ""
    )


def test_state_round_trip_and_legacy_migration(tmp_path):
    found, counts = parse()
    s = State(tmp_path)

    s.record_scan(IMG, "img:1", ["c1"], counts, found)

    s.last_rescan = 123.0

    s.save()

    s2 = State(tmp_path)

    s2.load()
    assert s2.alerted(IMG) == {k: f.tier for k, f in found.items()}
    assert s2.last_rescan == 123.0
    (tmp_path / "state.json").write_text(
        json.dumps({"images": {IMG: {"alerted": [PLAIN]}}, "meta": {}})
    )

    s3 = State(tmp_path)

    s3.load()
    assert s3.alerted(IMG) == {PLAIN: "normal"}


def test_escalation_counts_as_new_but_not_downgrade(tmp_path):
    found, counts = parse()
    s = State(tmp_path)
    s.images[IMG] = {"alerted": {k: "normal" for k in found}}

    assert set(s.new_findings(IMG, found)) == {KEV, DOS}  # escalated to urgent
    s.record_scan(IMG, "img:1", [], counts, found)

    calmer, _ = parse(Config(epss_threshold=1.0))  # DOS drops back to normal

    s.record_scan(IMG, "img:1", [], counts, calmer)
    assert (
        s.alerted(IMG)[DOS] == "urgent"
    )  # tiers only go up: no re-alert if EPSS rises again
    assert s.new_findings(IMG, found) == {}


class FakeNotifier:
    def __init__(self, ok=True):
        self.ok, self.calls = ok, []

    def find(self, tag):
        return iter([object()])

    def notify(self, **kw):
        self.calls.append(kw)

        return self.ok if kw["tag"] == "urgent" else True


def test_flush_sends_one_message_per_tier_and_rolls_back_failed_tier(tmp_path):
    found, counts = parse()
    state = State(tmp_path)

    state.record_scan(IMG, "img:1", [], counts, found)

    notifier = FakeNotifier(ok=False)  # urgent send fails, normal succeeds
    alerter = Alerter(Config(), notifier)

    alerter.add(ImageAlert(IMG, "img:1", [], True, found, dict.fromkeys(found)))
    alerter.flush(state)
    assert [c["tag"] for c in notifier.calls] == ["urgent", "normal"]

    urgent = notifier.calls[0]

    assert urgent["title"].startswith("🔴 URGENT: 2 new vulnerabilities")
    assert "· KEV · EPSS 100% · RCE" in urgent["body"]
    assert (
        "[CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013)"
        in urgent["body"]
    )
    assert "| KEV: 1" in urgent["body"]
    assert "CVE-2021-39537" not in urgent["body"]
    assert state.alerted(IMG) == {PLAIN: "normal"}  # urgent ones un-marked for retry
    assert alerter.pending == []


def test_format_groups_packages_and_puts_important_first():
    new = {
        "a": Finding("CVE-1", "Critical", "curl", "8.1", "", ""),
        "b": Finding("CVE-1", "Critical", "libcurl4t64", "8.1", "", ""),
        "c": Finding("CVE-2", "High", "pip", "23", "24", "", cls="RCE"),
        "d": Finding(
            "GHSA-x",
            "Medium",
            "lodash",
            "4",
            "",
            "https://github.com/advisories/GHSA-x",
            kev=True,
        ),
    }
    title, body = Alerter(Config(), FakeNotifier()).format(
        [ImageAlert(IMG, "img:1", ["c1"], False, new)]
    )
    lines = body.splitlines()

    assert title == "3 new vulnerabilities (1 critical, 1 high, 1 medium) in 1 image"
    assert lines[1] == "Critical: 1 | High: 1 | Medium: 1 | RCE: 1 | KEV: 1"
    assert (
        lines[2]
        == "- [GHSA-x](https://github.com/advisories/GHSA-x) [Medium] lodash 4 · KEV"
    )
    assert (
        lines[3]
        == "- [CVE-2](https://nvd.nist.gov/vuln/detail/CVE-2) [High] pip 23 (fix: 24) · RCE"
    )
    assert (
        lines[4]
        == "- [CVE-1](https://nvd.nist.gov/vuln/detail/CVE-1) [Critical] curl, libcurl4t64 8.1"
    )


def test_default_routing_sends_urgent_to_main_urls():
    a = Alerter(Config(apprise_urls="json://localhost/a"))

    assert len(list(a.notifier.find("urgent"))) == 1

    b = Alerter(
        Config(
            apprise_urls="json://localhost/a", apprise_urls_urgent="json://localhost/b"
        )
    )

    assert len(list(b.notifier.find("urgent"))) == 1
    assert len(list(b.notifier.find("normal"))) == 1


def test_newer_tag_stays_in_line_and_suffix():
    from semaphore.updates import newer_tag

    tags = [
        "1.27.2",
        "1.27.3",
        "1.27.10",
        "1.28.0",
        "1.27.11-alpine",
        "v1.27.12",
        "latest",
        "1.27",
    ]

    assert newer_tag("1.27.3", tags) == "1.27.10"  # numeric, not lexical; no 1.28 jump
    assert newer_tag("1.27.10", tags) is None
    assert newer_tag("1.27.3-alpine", tags) == "1.27.11-alpine"
    assert newer_tag("v1.27.3", tags) == "v1.27.12"
    assert (
        newer_tag("3.12-slim", ["3.13-slim", "3.14-slim", "4.0-slim", "3.14"])
        == "3.14-slim"
    )
    assert newer_tag("latest", tags) is None and newer_tag("3", ["4", "5"]) is None


def test_split_ref():
    from semaphore.updates import split_ref

    assert split_ref("nginx:1.27") == ("nginx", "1.27")
    assert split_ref("localhost:5000/app") == ("localhost:5000/app", "latest")
    assert split_ref("ghcr.io/a/b:v2") == ("ghcr.io/a/b", "v2")
    assert split_ref("nginx@sha256:abc") is None and split_ref("sha256:abc") is None


def candidate_without_kev():
    return {
        "matches": [
            m for m in SAMPLE["matches"] if m["vulnerability"]["id"] != "CVE-2021-42013"
        ]
    }


def test_update_check_scans_newer_tag_once_and_reports_fixes(tmp_path, monkeypatch):
    import semaphore.updates as updates
    from semaphore.scan import Scanner

    calls = []

    def fake_run(cmd, timeout, **kw):
        calls.append(cmd[:2])

        if cmd[:2] == ["crane", "digest"]:
            return {"httpd:2.4.49": "sha256:old\n", "httpd:2.4.69": "sha256:new\n"}[
                cmd[2]
            ]

        if cmd[:2] == ["crane", "ls"]:
            return "2.4.48\n2.4.49\n2.4.69\n2.4.70-alpine\n2.5.0\nlatest\n"

        Path(cmd[-1].split("=", 1)[1]).write_text("{}")  # syft

        return ""

    monkeypatch.setattr(updates, "run_tool", fake_run)

    cfg = Config(data_dir=tmp_path)

    cfg.sbom_dir.mkdir()

    scanner = Scanner(cfg)
    scanner.match = lambda sbom, only_fixed: json.dumps(candidate_without_kev())
    checker = updates.UpdateChecker(cfg, scanner)
    found, _ = parse()
    refs = [
        "abc12",
        "httpd:2.4.49",
        "httpd@sha256:old",
        "abc123",
    ]  # short ID hint first, bare ID last
    u = checker.check("sha256:abc123", refs, found)

    assert (u["ref"], u["pull"], u["fixes"]) == (
        "httpd:2.4.69",
        "httpd@sha256:new",
        [KEV],
    )
    checker.check("sha256:abc123", refs, found)
    assert calls.count(["syft", "scan"]) == 1  # SBOM cached by digest
    assert (
        checker.check("sha256:abc123", ["abc123"], found) is None
    )  # local build, no registry calls


def test_update_shows_in_alert_and_notice_retries_until_sent(tmp_path):
    found, counts = parse()
    update = {
        "ref": "httpd:2.4.69",
        "pull": "httpd@sha256:new",
        "digest": "sha256:new",
        "fixes": [KEV],
        "checked": "now",
    }
    state = State(tmp_path)

    state.record_scan(IMG, "httpd:2.4.49", ["web"], counts, found, update)

    class FailingNotice(FakeNotifier):
        def notify(self, **kw):
            self.calls.append(kw)

            return self.ok or not kw["title"].startswith("⬆")

    for ok in (False, True):
        notifier = FailingNotice(ok=ok)
        alerter = Alerter(Config(), notifier)

        alerter.add(
            ImageAlert(
                IMG, "httpd:2.4.49", ["web"], True, found, dict.fromkeys(found), update
            )
        )
        alerter.add_update(IMG, "httpd:2.4.49", ["web"], update, found)
        alerter.flush(state)
        assert state.update(IMG)["notified"] == ("sha256:new" if ok else None)

    urgent, normal, notice = notifier.calls

    assert (
        "⬆ httpd:2.4.69 fixes 1/2" in urgent["body"]
        and "· KEV · EPSS 100% · RCE · ⬆ fixed" in urgent["body"]
    )
    assert "⬆" not in normal["body"]
    assert (
        notice["tag"] == "normal" and notice["title"] == "⬆ 1 fixing update available"
    )
    assert (
        notice["body"] == "**httpd:2.4.49** (web) → httpd:2.4.69: fixes 1/3 (1 urgent)"
    )
    state.record_scan(
        IMG, "httpd:2.4.49", ["web"], counts, found, update
    )  # rescan keeps the mark
    assert state.update(IMG)["notified"] == "sha256:new"
    state.write_summary()

    row = json.loads(state.summary_path.read_text())["images"][0]

    assert row["update"] == {"ref": "httpd:2.4.69", "fixes": 1}
