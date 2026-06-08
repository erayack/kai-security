# CyberGym adapter — one-time setup

CyberGym (https://www.cybergym.io/) is an out-of-tree benchmark with a
large dataset and a Docker-based PoC verification server. This adapter
wraps the upstream CLI; the heavy bits (data, server) live outside this
repo.

## 1. Clone the upstream package

```bash
git clone https://github.com/sunblaze-ucb/cybergym.git ~/src/cybergym
cd ~/src/cybergym
uv venv && source .venv/bin/activate
pip install -e '.[dev,server]'
```

## 2. Fetch the dataset

The full task dataset is ~240 GB.

```bash
git lfs install
git clone https://huggingface.co/datasets/sunblaze-ucb/cybergym \
    ~/data/cybergym_data
```

For the per-task subset (~5 GB across the 10-task default subset built
into the adapter), use:

```bash
cd ~/src/cybergym
python scripts/server_data/download_subset.py
```

## 3. Run the submission server

```bash
cd ~/src/cybergym
python -m cybergym.server \
    --host 0.0.0.0 --port 8666 \
    --mask_map_path mask_map.json \
    --log_dir ./server_poc \
    --db_path ./server_poc/poc.db
```

The server defaults to Docker, so the daemon must be running.

## 4. Configure this adapter

Create an adapter config JSON (paths must be absolute):

```json
{
  "data_dir": "/Users/eren/data/cybergym_data/data",
  "mask_map": "/Users/eren/src/cybergym/mask_map.json",
  "server_url": "http://127.0.0.1:8666",
  "cybergym_pkg_root": "/Users/eren/src/cybergym",
  "difficulty": "level1",
  "submit": true
}
```

Save as `evaluation/adapters/cybergym/local_config.json` (gitignored).

## 5. Drive the adapter

```bash
# enumerate the built-in 10-task subset
uv run python -m evaluation.cli list \
    --adapter cybergym \
    --adapter-config @evaluation/adapters/cybergym/local_config.json

# run a single task end-to-end
uv run python -m evaluation.cli run \
    --adapter cybergym \
    --adapter-config @evaluation/adapters/cybergym/local_config.json \
    --tasks arvo:10400 \
    --limit 1

# live progress
uv run python -m evaluation.cli watch output/bench/cybergym/run_<id>
```

## 6. Known limitations

* CyberGym wants a *binary* PoC — the bytes that crash a fuzz harness.
  kai today emits high-level Python / shell PoC code. The adapter
  collects any binary the agent writes at `<repo>/poc` (plus a few
  other common names) and falls back to base64 / hex markers embedded
  in `ExploitRecord.poc_code`. Until kai's prompts are tuned for this
  task shape, expect most tasks to fail with `failure_reason="no_poc_binary"`.
  That is a useful failure mode — it lights up the work needed to make
  the agent productive on this benchmark.
* The agent does not run inside the CyberGym Docker network. We do not
  use `cybergym.firewall`, which means the agent has full internet
  access during a task. Re-enable the firewall before publishing any
  numbers you intend to compare to the upstream leaderboard.
