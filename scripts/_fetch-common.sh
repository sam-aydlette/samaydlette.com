#!/usr/bin/env bash
# Shared by the detection-feed fetch scripts (fetch-detection-feeds.sh and
# fetch-aws-feeds.sh). Sourced, never run.

fail() {  # fail FILE REASON
  rm -f "$1"
  # One line, no workflow-command syntax: the reason can carry API error text.
  # It is published (the detection summary), so AWS account IDs in an error's
  # ARNs are masked as scripts/_redact.py masks them.
  printf '%s' "$2" | tr '\r\n' '  ' | sed -e 's/::/:/g' -e 's/:[0-9]\{12\}:/:ACCOUNT:/g' -e 's/[0-9]\{12\}/ACCOUNT/g' \
    | head -c 300 > "$1.error"
  echo "::warning::$1: $(head -c 200 "$1.error")"
}
