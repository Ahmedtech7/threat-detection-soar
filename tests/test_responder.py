import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "responder"))
import custom_soar as soar  # noqa: E402

CFG = {
    "abuseipdb_key": "k1",
    "virustotal_key": "k2",
    "abuse_threshold": 75,
    "vt_threshold": 3,
    "wazuh_api_url": "https://wazuh:55000",
    "wazuh_api_user": "u",
    "wazuh_api_password": "p",
    "verify_tls": False,
}

SSH_ALERT = {
    "rule": {"id": "100106", "description": "SSH brute force from 45.33.32.156"},
    "agent": {"id": "003"},
    "data": {"srcip": "45.33.32.156"},
}


@pytest.mark.parametrize(
    "alert, expected",
    [
        ({"data": {"srcip": "8.8.8.8"}}, "8.8.8.8"),
        ({"data": {"srcip": "192.168.1.5"}}, None),  # private
        ({"data": {"srcip": "127.0.0.1"}}, None),  # loopback
        ({"data": {"srcip": "not-an-ip"}}, None),
        ({"data": {"win": {"eventdata": {"sourceIp": "1.1.1.1"}}}}, "1.1.1.1"),
        ({"data": {"srcip": "10.0.0.1", "win": {"eventdata": {"ipAddress": "9.9.9.9"}}}}, "9.9.9.9"),
        ({}, None),
    ],
)
def test_extract_ip(alert, expected):
    assert soar.extract_ip(alert) == expected


@pytest.mark.parametrize(
    "intel, expected",
    [
        ({"abuseipdb_score": 90}, True),
        ({"abuseipdb_score": 74, "vt_malicious": 2}, False),
        ({"vt_malicious": 3}, True),
        ({}, False),  # no intel never blocks
    ],
)
def test_is_malicious(intel, expected):
    assert soar.is_malicious(intel, CFG) is expected


def test_private_ip_is_skipped_without_lookups(monkeypatch):
    monkeypatch.setattr(soar, "enrich", lambda *a: pytest.fail("must not call APIs"))
    record = soar.handle({"data": {"srcip": "10.1.2.3"}}, CFG)
    assert record["soar"]["action"] == "skipped_no_public_ip"


def test_malicious_ip_is_blocked_on_alert_agent(monkeypatch):
    monkeypatch.setattr(soar, "abuseipdb_score", lambda ip, k: 100)
    monkeypatch.setattr(soar, "virustotal_malicious", lambda ip, k: 0)
    calls = []
    monkeypatch.setattr(soar, "block_ip", lambda ip, agent, cfg: calls.append((ip, agent)))
    record = soar.handle(SSH_ALERT, CFG)
    assert record["soar"]["action"] == "blocked"
    assert calls == [("45.33.32.156", "003")]


def test_clean_ip_is_only_enriched(monkeypatch):
    monkeypatch.setattr(soar, "abuseipdb_score", lambda ip, k: 0)
    monkeypatch.setattr(soar, "virustotal_malicious", lambda ip, k: 0)
    monkeypatch.setattr(soar, "block_ip", lambda *a: pytest.fail("must not block"))
    record = soar.handle(SSH_ALERT, CFG)
    assert record["soar"]["action"] == "enriched_only"
    assert record["soar"]["intel"] == {"abuseipdb_score": 0, "vt_malicious": 0}


def test_one_failing_source_does_not_stop_the_other(monkeypatch):
    def down(ip, key):
        raise urllib.error.URLError("timeout")

    monkeypatch.setattr(soar, "abuseipdb_score", down)
    monkeypatch.setattr(soar, "virustotal_malicious", lambda ip, k: 5)
    monkeypatch.setattr(soar, "block_ip", lambda *a: None)
    record = soar.handle(SSH_ALERT, CFG)
    assert record["soar"]["action"] == "blocked"
    assert "abuseipdb_score_error" in record["soar"]["intel"]


def test_block_failure_is_logged_not_raised(monkeypatch):
    monkeypatch.setattr(soar, "abuseipdb_score", lambda ip, k: 100)
    monkeypatch.setattr(soar, "virustotal_malicious", lambda ip, k: 0)

    def api_down(*a):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(soar, "block_ip", api_down)
    record = soar.handle(SSH_ALERT, CFG)
    assert record["soar"]["action"] == "block_failed"


def test_block_ip_calls_wazuh_api(monkeypatch):
    sent = []

    def fake_http(url, headers=None, data=None, method=None, verify=True):
        sent.append((method, url, headers, data))
        return {"data": {"token": "T", "total_affected_items": 1}}

    monkeypatch.setattr(soar, "http_json", fake_http)
    soar.block_ip("45.33.32.156", "003", CFG)
    (m1, u1, _, _), (m2, u2, h2, d2) = sent
    assert (m1, u1) == ("POST", "https://wazuh:55000/security/user/authenticate")
    assert (m2, u2) == ("PUT", "https://wazuh:55000/active-response?agents_list=003")
    assert h2["Authorization"] == "Bearer T"
    assert json.loads(d2) == {"command": "firewall-drop", "alert": {"data": {"srcip": "45.33.32.156"}}}


def test_main_writes_one_log_line(tmp_path, monkeypatch):
    cfg_file = tmp_path / "soar.json"
    log_file = tmp_path / "soar.log"
    cfg_file.write_text(json.dumps({**CFG, "log_file": str(log_file)}))
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps({"rule": {"id": "100103"}, "data": {}}))
    monkeypatch.setattr(soar, "CONFIG_PATH", str(cfg_file))
    assert soar.main(["custom-soar", str(alert_file)]) == 0
    line = json.loads(log_file.read_text().strip())
    assert line["soar"]["action"] == "skipped_no_public_ip"



def test_block_ip_raises_when_wazuh_ran_nothing(monkeypatch):
    # Real reply from Wazuh 4.12 when the target is the manager itself (HTTP 200).
    reply = {
        "data": {
            "token": "T",
            "total_affected_items": 0,
            "failed_items": [{"error": {"code": 1703, "message": "Action not available for Manager (agent 000)"}}],
        },
        "message": "AR command was not sent to any agent",
    }
    monkeypatch.setattr(soar, "http_json", lambda *a, **k: reply)
    with pytest.raises(ValueError, match="agent 000"):
        soar.block_ip("45.33.32.156", "000", CFG)
