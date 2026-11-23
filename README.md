# Threat Detection & Automated Response Platform

A SIEM + SOAR project built on **Wazuh** and **Sysmon**. It detects attacks on Windows and Linux endpoints with custom rules written in **Sigma** and mapped to **MITRE ATT&CK**. It enriches alerts with threat intelligence from **AbuseIPDB** and **VirusTotal**, and it blocks malicious IPs automatically.

```
 Windows endpoint                Linux endpoint
 Sysmon + Security log           /var/log/auth.log
        │  Wazuh agent                  │  Wazuh agent
        └──────────────┬────────────────┘
                       ▼
               Wazuh manager ── custom rules (wazuh/rules/local_rules.xml)
                       │         translated from Sigma (sigma/)
        ┌──────────────┴───────────────┐
        ▼                              ▼
 Active response                 custom-soar integration (responder/)
 firewall-drop on                 1. take the source IP
 SSH brute force                  2. AbuseIPDB + VirusTotal lookup
                                  3. malicious? → Wazuh API → firewall-drop
                                  4. log the decision (soar.json)
```

## Detections

| Wazuh rule | Sigma rule | Detects | MITRE ATT&CK |
|---|---|---|---|
| 100100 | [proc_creation_encoded_powershell](sigma/windows/proc_creation_encoded_powershell.yml) | PowerShell run with a Base64 encoded command | T1059.001, T1027 |
| 100101 | [proc_access_lsass](sigma/windows/proc_access_lsass.yml) | A process reading LSASS memory (credential dumping) | T1003.001 |
| 100102 | [win_security_admin_group_add](sigma/windows/win_security_admin_group_add.yml) | Account added to local Administrators | T1098 |
| 100103 | [proc_creation_schtasks_create](sigma/windows/proc_creation_schtasks_create.yml) | Scheduled task created for persistence | T1053.005 |
| 100104 | [proc_creation_certutil_download](sigma/windows/proc_creation_certutil_download.yml) | certutil used to download a payload | T1105 |
| 100106 | [lnx_sshd_failed_auth](sigma/linux/lnx_sshd_failed_auth.yml) | SSH brute force (repeated failures from one IP) | T1110.001 |
| 100107 | [lnx_new_local_user](sigma/linux/lnx_new_local_user.yml) | New local user created | T1136.001 |

The Sigma rules are the source of truth. Each Wazuh rule carries `<info>sigma:<id></info>` to link it to its Sigma rule, and the tests check that the two stay in sync.

## Automated response

`responder/custom_soar.py` is a Wazuh integration. It uses only the Python standard library, so it runs on Wazuh's bundled Python. For every alert of level 10 or higher:

1. It extracts the public source IP. Private and loopback IPs are skipped.
2. It looks the IP up on AbuseIPDB (confidence score) and VirusTotal (number of engines that flag it).
3. It blocks the IP if AbuseIPDB scores it at least 75, or if at least 3 VirusTotal engines flag it. The block runs `firewall-drop` through the Wazuh API on the agent that raised the alert.
4. It writes every decision (`blocked`, `enriched_only`, `skipped_no_public_ip`, `block_failed`) as one JSON line to `/var/ossec/logs/soar.json`.

If one intel source is down, the other is still used. A failed block is logged, never silently ignored.

## Testing

**Unit tests** cover the responder logic and the Sigma ↔ Wazuh mapping, and include a pySigma validation of every rule. They run in CI on every push.

```bash
pip install -r requirements-dev.txt
pytest -v
```

**Engine test** starts a real Wazuh 4.12 manager in Docker, loads the rules and sends sample events into its analysis queue, in the same format the Windows and Linux agents use. It then checks that each expected rule fires. It also checks one negative case: Windows Defender reading LSASS must not alert.

**Blocking test:** the responder's `block_ip` was run against a real Wazuh 4.12 manager with an enrolled Ubuntu agent. The agent then added `-A INPUT -s 45.33.32.156/32 -j DROP` to its iptables rules.

```bash
sh tests/run_engine_test.sh
```

```
PASS  expected 100100  got ['100100']
PASS  expected 100103  got ['100103']
PASS  expected 100104  got ['100104']
PASS  expected 100101  got ['100101']
PASS  expected no alert (Defender reading LSASS must NOT alert (filter_system))  got none
PASS  expected 100102  got ['100102']
PASS  expected 100106  got ['100106']
PASS  expected 100107  got ['100107']
8/8 passed
```

## Setup

1. **Wazuh manager:** use the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) single-node deployment, or the Wazuh OVA.
2. **Rules and responder:** copy this repo to the manager and run `sh deploy/install-manager.sh`. Then:
   - put your API keys in `/var/ossec/etc/soar.json` (free keys from AbuseIPDB and VirusTotal);
   - paste `wazuh/manager.conf` into the manager's `ossec.conf`;
   - restart the manager.
3. **Windows VM:**
   - install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with `sysmon64.exe -accepteula -i sysmon/sysmonconfig.xml`;
   - install the Wazuh agent and add `wazuh/agent-windows.conf` to its config.
4. **Linux VM:** install the Wazuh agent and add `wazuh/agent-linux.conf` to its config.
5. **Simulate attacks** (test machines you own only):
   - Windows, as Administrator: `simulate/windows_tests.ps1`
   - Linux, from a second machine: `sh simulate/linux_ssh_bruteforce.sh <target-ip>`
   - Linux, as root on the target: `sh simulate/linux_new_user.sh`

## Project layout

```
sigma/        Sigma detection rules (Windows + Linux)
wazuh/        Wazuh rules and manager/agent config snippets
sysmon/       Minimal Sysmon config for the events the rules need
responder/    SOAR integration: enrichment + automatic blocking
simulate/     Harmless scripts that trigger each detection
tests/        Unit tests + real Wazuh engine test
deploy/       Install script for the manager
```

## Security notes

- `soar.json` holds API keys. The install script sets it to `640 root:wazuh`, and it is git-ignored.
- `verify_tls: false` is only for testing with Wazuh's self-signed certificate. Use a trusted certificate and set it to `true` anywhere else.
- Run the simulation scripts only on machines you own.
