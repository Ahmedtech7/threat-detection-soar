"""Checks that the Sigma rules and the Wazuh rules stay in sync."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_FILES = sorted((ROOT / "sigma").rglob("*.yml"))
REQUIRED = {"title", "id", "status", "description", "logsource", "detection", "level", "tags"}


def wazuh_rules():
    # local_rules.xml holds several top-level <group> elements; wrap them to parse.
    text = (ROOT / "wazuh/rules/local_rules.xml").read_text()
    root = ET.fromstring(f"<root>{text}</root>")
    rules = {}
    for rule in root.iter("rule"):
        info = rule.findtext("info") or ""
        if info.startswith("sigma:"):
            rules[info.removeprefix("sigma:")] = rule
    return rules


def attack_ids(sigma):
    return {t.split(".", 1)[1].upper() for t in sigma["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)}


def test_sigma_rules_exist():
    assert len(SIGMA_FILES) >= 7


@pytest.mark.parametrize("path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_is_valid_and_mapped(path):
    sigma = yaml.safe_load(path.read_text())
    assert REQUIRED <= sigma.keys()
    assert "condition" in sigma["detection"]
    assert sigma["level"] in {"informational", "low", "medium", "high", "critical"}
    ids = attack_ids(sigma)
    assert ids, "every rule needs at least one MITRE ATT&CK technique tag"

    rule = wazuh_rules().get(sigma["id"])
    assert rule is not None, f"no Wazuh rule carries <info>sigma:{sigma['id']}</info>"
    assert {i.text for i in rule.iter("id")} == ids


def test_wazuh_rule_ids_are_unique_and_custom():
    rules = wazuh_rules().values()
    ids = [int(r.get("id")) for r in rules]
    assert len(ids) == len(set(ids))
    assert all(100000 <= i <= 120000 for i in ids)  # Wazuh's range for local rules


def test_sigma_rules_pass_pysigma_validation():
    collection = pytest.importorskip("sigma.collection")
    rules = collection.SigmaCollection.load_ruleset([str(p) for p in SIGMA_FILES], collect_errors=True)
    assert [(r.title, r.errors) for r in rules.rules if r.errors] == []
