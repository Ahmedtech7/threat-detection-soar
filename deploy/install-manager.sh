#!/bin/sh
# Installs the rules and the SOAR responder into a running Wazuh manager.
# Usage (on the manager, as root):  sh deploy/install-manager.sh
# Docker single-node: docker cp the repo into the manager container and run it there.
set -eu
OSSEC=/var/ossec
REPO=$(cd "$(dirname "$0")/.." && pwd)

cp "$REPO/wazuh/rules/local_rules.xml" "$OSSEC/etc/rules/local_rules.xml"
cp "$REPO/responder/custom-soar" "$REPO/responder/custom_soar.py" "$OSSEC/integrations/"
chown root:wazuh "$OSSEC/integrations/custom-soar" "$OSSEC/integrations/custom_soar.py"
chmod 750 "$OSSEC/integrations/custom-soar" "$OSSEC/integrations/custom_soar.py"

if [ ! -f "$OSSEC/etc/soar.json" ]; then
  cp "$REPO/responder/soar.example.json" "$OSSEC/etc/soar.json"
  chown root:wazuh "$OSSEC/etc/soar.json"
  chmod 640 "$OSSEC/etc/soar.json"   # holds API keys
  echo "Edit $OSSEC/etc/soar.json with your API keys."
fi

echo "Now paste wazuh/manager.conf into $OSSEC/etc/ossec.conf, then:"
echo "  $OSSEC/bin/wazuh-control restart"
