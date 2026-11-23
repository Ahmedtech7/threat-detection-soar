#!/bin/sh
# Triggers rule 100106 by failing SSH logins 10 times against YOUR OWN test host.
# Run it from a second test machine, not from the target itself
# (127.0.0.1 is private, so the SOAR responder will only skip it).
# Usage: sh simulate/linux_ssh_bruteforce.sh <target-ip>
set -eu
TARGET=${1:?usage: $0 <target-ip>}
for i in $(seq 1 10); do
  ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
      "fakeuser$i@$TARGET" true 2>/dev/null || true
done
echo "Done. Check the Wazuh dashboard for rule 100106."
