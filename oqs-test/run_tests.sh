#!/bin/bash

set -e

###########
# Run OpenSSH regression tests
###########

INVESTIGATE_FURTHER="integrity \
                     keys-command \
                     hostkey-agent \
                     authinfo \
                     principals-command"
SKIPPED_DUE_TO_CERTIFIED_KEYS="agent \
                               cert-hostkey \
                               cert-userkey \
                               cert-file \
                               sshsig"
make tests -e SKIP_LTESTS="${INVESTIGATE_FURTHER} ${SKIPPED_DUE_TO_CERTIFIED_KEYS}"
