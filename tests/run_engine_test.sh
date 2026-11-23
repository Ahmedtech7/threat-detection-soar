#!/bin/sh
# Starts a throwaway Wazuh manager in Docker, loads our rules, replays the samples.
set -eu
cd "$(dirname "$0")/.."
IMAGE=wazuh/wazuh-manager:4.12.0
docker rm -f wazuh-rule-test >/dev/null 2>&1 || true
docker run -d --name wazuh-rule-test "$IMAGE" >/dev/null
trap 'docker rm -f wazuh-rule-test >/dev/null' EXIT
echo "Waiting for Wazuh to start..."
until docker exec wazuh-rule-test test -S /var/ossec/queue/sockets/queue 2>/dev/null; do sleep 5; done
docker cp wazuh/rules/local_rules.xml wazuh-rule-test:/var/ossec/etc/rules/local_rules.xml
docker exec wazuh-rule-test /var/ossec/bin/wazuh-control restart >/dev/null
sleep 15
docker cp tests/. wazuh-rule-test:/tmp/tests
docker exec wazuh-rule-test /var/ossec/framework/python/bin/python3 /tmp/tests/wazuh_engine_test.py
