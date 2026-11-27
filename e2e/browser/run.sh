#!/bin/sh
# Builds sparrow-hub and echo-node, starts the hub with the Web Profile on
# and a spawned echo node, and runs the browser client (run.cjs) against it.
# Requires Go, Node and Playwright with Chromium (`require('playwright')`).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root/go"
SPARROW_BROWSER=1 exec go test -count=1 -run TestBrowser -v ./cmd/sparrow-hub
