#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=0.7.0

# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
)

# Fetch libbpf release and extract the desired headers
mkdir libbpf-work && cd libbpf-work
curl -OL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz"
tar -zxvf "v${LIBBPF_VERSION}.tar.gz" --strip-components 1

