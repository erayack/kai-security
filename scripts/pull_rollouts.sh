#!/bin/bash
# Pull live per-agent rollouts off Railway cybergym + evmbench workers.
# Tars only state/ subdirs (skips repo-vul.tar.gz + prepared/ input data).
# Overwrites existing files in docs/rollouts-2026-05-21-real/.

set -u
DEST_BASE="${DEST_BASE:-docs/rollouts-2026-05-21-real}"

pull_one() {
  local svc="$1"
  local dest="$DEST_BASE/$2"
  mkdir -p "$dest"
  local tmp; tmp="$(mktemp -t pull_rollouts)"
  if ! railway ssh --service "$svc" -- "cd /app/output/bench/$2 && find . -path '*/state/*' -type f 2>/dev/null | tar czf - -h -T - | base64" 2>/dev/null > "$tmp"; then
    echo "$svc: ssh failed" >&2
    rm "$tmp"
    return 1
  fi
  local sz; sz=$(wc -c < "$tmp")
  if [ "$sz" -lt 200 ]; then
    echo "$svc: pull empty ($sz bytes)" >&2
    rm "$tmp"
    return 1
  fi
  tr -d '\r' < "$tmp" | base64 -d | tar xzf - -C "$dest" 2>/dev/null
  rm "$tmp"
  local n; n=$(find "$dest" -type f -name '*.jsonl' 2>/dev/null | wc -l)
  local size; size=$(du -sh "$dest" 2>/dev/null | awk '{print $1}')
  echo "$svc: pulled $n .jsonl files, total $size"
}

pull_one kai-bench-cybergym-v2 cybergym
pull_one kai-bench-evmbench evmbench
