#!/bin/bash
# Pull benchmark rollouts from EACH Railway replica by deployment-instance UUID.
# worker_id in bench_tasks == RAILWAY_REPLICA_ID == deployment-instance UUID
# (see evaluation/worker.py:460-464).
#
# Override which benchmark + service + run with env vars:
#   BENCHMARK=evmbench SERVICE=kai-bench-evmbench RUN_PREFIX=3d9e29 \
#     DEST=docs/rollouts-2026-05-26-r-evm bash scripts/pull_rollouts_per_replica.sh
#
# Defaults to cybergym. SERVICE auto-derives from BENCHMARK if not set
# (cybergym → kai-bench-cybergym-v2, evmbench → kai-bench-evmbench).

set -u
BENCHMARK="${BENCHMARK:-cybergym}"
case "$BENCHMARK" in
  cybergym) DEFAULT_SERVICE="kai-bench-cybergym-v2" ;;
  evmbench) DEFAULT_SERVICE="kai-bench-evmbench" ;;
  *) DEFAULT_SERVICE="kai-bench-${BENCHMARK}" ;;
esac
DEST="${DEST:-docs/rollouts-2026-05-21-real/$BENCHMARK}"
RUN_PREFIX="${RUN_PREFIX:-ced1b}"
SERVICE="${SERVICE:-$DEFAULT_SERVICE}"
REMOTE_DIR="${REMOTE_DIR:-/app/output/bench/$BENCHMARK}"
mkdir -p "$DEST"

export DB_URL="$(railway variables --service Postgres --json 2>/dev/null | jq -r .DATABASE_PUBLIC_URL)"
export RUN_PREFIX
export BENCHMARK
if [ -z "$DB_URL" ] || [ "$DB_URL" = "null" ]; then
  echo "ERROR: could not read DATABASE_PUBLIC_URL from Railway" >&2
  exit 1
fi

ROWS_FILE="$(mktemp -t pull_rows)"
uv run python - > "$ROWS_FILE" <<'PY'
import psycopg, os
from psycopg.rows import dict_row
with psycopg.connect(os.environ["DB_URL"], row_factory=dict_row) as c:
    cur = c.cursor()
    cur.execute(
        "SELECT DISTINCT worker_id, task_id FROM bench_tasks "
        "WHERE benchmark=%s AND run_id LIKE %s AND worker_id IS NOT NULL "
        "ORDER BY task_id",
        (os.environ["BENCHMARK"], os.environ["RUN_PREFIX"] + "%"),
    )
    for r in cur.fetchall():
        print(f"{r['worker_id']}\t{r['task_id']}")
PY

n_rows=$(wc -l < "$ROWS_FILE" | tr -d ' ')
if [ "$n_rows" -eq 0 ]; then
  echo "no worker_ids found (benchmark='$BENCHMARK' run prefix '$RUN_PREFIX')" >&2
  rm -f "$ROWS_FILE"
  exit 1
fi

echo "Pulling from $n_rows replicas (benchmark=$BENCHMARK service=$SERVICE run prefix '$RUN_PREFIX')..."
echo

OK=0
FAIL=0
HOSTS_SEEN=""
while IFS=$'\t' read -r uuid task; do
  [ -z "$uuid" ] && continue
  tmp="$(mktemp -t pull_per_replica)"
  if ! railway ssh --service "$SERVICE" --deployment-instance "$uuid" -- \
        "hostname && cd $REMOTE_DIR 2>/dev/null && \
         { find . -path '*/state/*' -type f 2>/dev/null; \
           find . -name 'stderr.log' -type f 2>/dev/null; \
           find . -name 'stdout.log' -type f 2>/dev/null; } | \
         tar czf - -h -T - 2>/dev/null | base64" 2>/dev/null > "$tmp"; then
    echo "[$task] ssh FAILED uuid=$uuid"
    rm -f "$tmp"
    FAIL=$((FAIL+1))
    continue
  fi
  host="$(head -1 "$tmp")"
  if [ -z "$host" ]; then
    echo "[$task] ssh returned empty uuid=$uuid"
    rm -f "$tmp"
    FAIL=$((FAIL+1))
    continue
  fi
  HOSTS_SEEN="$HOSTS_SEEN $host"
  tail -n +2 "$tmp" | tr -d '\r' | base64 -d 2>/dev/null | tar xzf - -C "$DEST" 2>/dev/null
  rm -f "$tmp"
  files=$(find "$DEST"/run_${RUN_PREFIX}*/"$task" -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
  size=$(du -sh "$DEST"/run_${RUN_PREFIX}*/"$task" 2>/dev/null | awk '{print $1}' | head -1)
  echo "[$task] host=$host  ${files} jsonl  ${size:-0}  uuid=${uuid:0:8}"
  OK=$((OK+1))
done < "$ROWS_FILE"
rm -f "$ROWS_FILE"

echo
echo "--- summary ---"
echo "ok=$OK fail=$FAIL"
echo "unique hosts:$(echo $HOSTS_SEEN | tr ' ' '\n' | sort -u | tr '\n' ' ')"
echo "--- task dirs ---"
find "$DEST"/run_${RUN_PREFIX}* -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort
