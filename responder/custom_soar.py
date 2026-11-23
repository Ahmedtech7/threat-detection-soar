#!/usr/bin/env python3
"""Wazuh integration: enrich an alert's source IP and block it if malicious.

Wazuh's integratord calls this with the path of a JSON alert file:
    custom-soar <alert_file> [api_key] [hook_url]

Steps
  1. Pull the source IP out of the alert; skip private / reserved IPs.
  2. Look it up on AbuseIPDB and VirusTotal.
  3. If either source says it is malicious, ask the Wazuh API to run the
     firewall-drop active response on the agent that raised the alert.
  4. Write one JSON line per decision to the SOAR log (shows up in Wazuh
     when that file is added as a <localfile> with log_format json).

Settings come from a JSON file (default /var/ossec/etc/soar.json), see
responder/soar.example.json. Only the standard library is used, so it runs
on Wazuh's bundled Python without installing anything.
"""
import base64
import ipaddress
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

CONFIG_PATH = os.environ.get("SOAR_CONFIG", "/var/ossec/etc/soar.json")
TIMEOUT = 10

# Alert fields that can hold the attacker's IP, in order of preference.
IP_FIELDS = (
    ("data", "srcip"),
    ("data", "win", "eventdata", "sourceIp"),
    ("data", "win", "eventdata", "ipAddress"),
)


def load_config(path=None):
    with open(path or CONFIG_PATH) as f:
        cfg = json.load(f)
    cfg.setdefault("abuse_threshold", 75)  # AbuseIPDB confidence 0-100
    cfg.setdefault("vt_threshold", 3)      # engines that flag the IP
    cfg.setdefault("log_file", "/var/ossec/logs/soar.json")
    cfg.setdefault("verify_tls", True)
    return cfg


def extract_ip(alert):
    """Return the first public source IP in the alert, or None."""
    for path in IP_FIELDS:
        value = alert
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return None


def http_json(url, headers=None, data=None, method=None, verify=True):
    req = urllib.request.Request(url, headers=headers or {}, data=data, method=method)
    ctx = None if verify else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return json.load(resp)


def abuseipdb_score(ip, key):
    body = http_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": key, "Accept": "application/json"},
    )
    return body["data"]["abuseConfidenceScore"]


def virustotal_malicious(ip, key):
    body = http_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key},
    )
    return body["data"]["attributes"]["last_analysis_stats"]["malicious"]


def enrich(ip, cfg):
    """Query each configured source. A failing source is recorded, not fatal."""
    intel = {}
    sources = (
        ("abuseipdb_score", abuseipdb_score, cfg.get("abuseipdb_key")),
        ("vt_malicious", virustotal_malicious, cfg.get("virustotal_key")),
    )
    for name, lookup, key in sources:
        if not key:
            continue
        try:
            intel[name] = lookup(ip, key)
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as e:
            intel[name + "_error"] = str(e)
    return intel


def is_malicious(intel, cfg):
    return (
        intel.get("abuseipdb_score", 0) >= cfg["abuse_threshold"]
        or intel.get("vt_malicious", 0) >= cfg["vt_threshold"]
    )


def block_ip(ip, agent_id, cfg):
    """Run firewall-drop on the agent through the Wazuh API."""
    api = cfg["wazuh_api_url"].rstrip("/")
    verify = cfg["verify_tls"]
    creds = base64.b64encode(f"{cfg['wazuh_api_user']}:{cfg['wazuh_api_password']}".encode()).decode()
    token = http_json(
        f"{api}/security/user/authenticate",
        headers={"Authorization": f"Basic {creds}"},
        method="POST",
        verify=verify,
    )["data"]["token"]
    payload = {"command": "firewall-drop", "alert": {"data": {"srcip": ip}}}
    result = http_json(
        f"{api}/active-response?agents_list={agent_id}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(payload).encode(),
        method="PUT",
        verify=verify,
    )
    # Wazuh answers 200 even when no agent ran the command (e.g. agent 000 = the manager).
    if not result["data"]["total_affected_items"]:
        failed = result["data"].get("failed_items") or [{}]
        raise ValueError(failed[0].get("error", {}).get("message", result.get("message")))
    return result


def handle(alert, cfg):
    """Decide what to do with one alert. Returns the record that gets logged."""
    rule = alert.get("rule", {})
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "soar": {"rule_id": rule.get("id"), "rule": rule.get("description")},
    }
    ip = extract_ip(alert)
    if not ip:
        record["soar"]["action"] = "skipped_no_public_ip"
        return record
    intel = enrich(ip, cfg)
    record["soar"].update(srcip=ip, intel=intel)
    if not is_malicious(intel, cfg):
        record["soar"]["action"] = "enriched_only"
        return record
    agent_id = alert.get("agent", {}).get("id", "000")
    try:
        block_ip(ip, agent_id, cfg)
        record["soar"]["action"] = "blocked"
        record["soar"]["agent_id"] = agent_id
    except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as e:
        record["soar"]["action"] = "block_failed"
        record["soar"]["error"] = str(e)
    return record


def main(argv):
    if len(argv) < 2:
        print("usage: custom-soar <alert_file>", file=sys.stderr)
        return 1
    cfg = load_config()
    with open(argv[1]) as f:
        alert = json.load(f)
    record = handle(alert, cfg)
    with open(cfg["log_file"], "a") as f:
        f.write(json.dumps(record) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
