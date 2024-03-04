#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/oqs"}

cd oqs-scripts/tmp/liboqs
rm -rf build
mkdir build && cd build
cmake .. -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${PREFIX}
ninja
ninja install
