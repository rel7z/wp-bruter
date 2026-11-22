#!/bin/bash
# Build the fleet binary. Workers are linux/amd64, so never ship the local
# macOS build: a bare copy fails with "Exec format error".
set -eu
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-amd64}" \
    go build -trimpath -ldflags "-s -w" -o wp-bruter .
file wp-bruter
