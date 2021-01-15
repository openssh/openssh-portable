#!/bin/sh

. .github/configs $1 $2

set -x
./configure ${CONFIGFLAGS}
