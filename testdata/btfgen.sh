#!/bin/bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

TMPDIR=$1
ARCH=$2
FROM=$3
OUTPUT=$4

echo "btfhub-archive is a big archive project, maybe take some times..."
if [ -f "$TMPDIR/btfhub" ]; then
    git clone --depth 1 https://github.com/aquasecurity/btfhub $TMPDIR/btfhub
fi
if [ -f "$TMPDIR/btfhub-archive" ]; then
    git clone --depth 1 https://github.com/aquasecurity/btfhub-archive/ $TMPDIR/btfhub-archive/
    mv $TMPDIR/btfhub-archive/* $TMPDIR/btfhub/archive/
fi

${TMPDIR}/btfhub/tools/btfgen.sh -a ${ARCH} \
  -o $FROM/tcpconnect/bpf_bpfel.o \
  -o $FROM/tcptrace/bpf_bpfel.o \
  -o $FROM/tcpdrop/bpf_bpfel.o
mkdir -p ${OUTPUT}
cp -r ${TMPDIR}/btfhub/custom-archive/* ${OUTPUT}