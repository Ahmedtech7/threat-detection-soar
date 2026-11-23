#!/bin/sh
# Triggers rule 100107, then removes the test user. Run as root on a test machine.
set -eu
useradd soar_test_user
userdel soar_test_user
echo "Done. Check the Wazuh dashboard for rule 100107."
