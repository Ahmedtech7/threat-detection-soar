"""End-to-end test of the Wazuh rules inside a real Wazuh manager.

Sends each sample in engine_samples.json into the manager's analysis queue in
the same format a Windows or Linux agent uses, then checks alerts.json for the
expected rule ID. A sample with "expect": null must raise none of our rules.

Run with:  sh tests/run_engine_test.sh   (needs Docker)
"""
import json
import socket
import sys
import time
from html import escape
from pathlib import Path

QUEUE = "/var/ossec/queue/sockets/queue"
ALERTS = Path("/var/ossec/logs/alerts/alerts.json")
OUR_RULES = range(100100, 100200)


def windows_event(s):
    """Build the {"Message", "Event": <XML>} payload the Windows agent sends."""
    data = "".join(f"<Data Name='{k}'>{escape(v)}</Data>" for k, v in s["data"].items())
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{s['provider']}'/><EventID>{s['event_id']}</EventID>"
        f"<Level>{s.get('level', 4)}</Level><Keywords>{s.get('keywords', '0x8000000000000000')}</Keywords>"
        "<TimeCreated SystemTime='2026-11-23T10:00:00.000Z'/>"
        f"<Channel>{s['channel']}</Channel><Computer>WIN-HOST</Computer>"
        f"</System><EventData>{data}</EventData></Event>"
    )
    return "f:EventChannel:" + json.dumps({"Message": "", "Event": xml})


def send_and_collect(sample):
    start = ALERTS.stat().st_size
    if sample["type"] == "windows":
        messages = [windows_event(sample)]
    else:
        messages = [f"1:{sample['location']}:{sample['line']}"] * sample.get("repeat", 1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(QUEUE)
        for m in messages:
            sock.send(m.encode())
            time.sleep(0.2)
    time.sleep(3)
    with ALERTS.open() as f:
        f.seek(start)
        return {json.loads(line)["rule"]["id"] for line in f if line.strip()}


def main():
    samples = json.loads((Path(__file__).parent / "engine_samples.json").read_text())
    failed = 0
    for s in samples:
        fired = send_and_collect(s)
        ours = sorted(r for r in fired if int(r) in OUR_RULES)
        ok = ours == ([s["expect"]] if s["expect"] else [])
        failed += not ok
        label = s["expect"] or "no alert (" + s.get("note", "") + ")"
        print(f"{'PASS' if ok else 'FAIL'}  expected {label}  got {ours or 'none'}")
    print(f"{len(samples) - failed}/{len(samples)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
