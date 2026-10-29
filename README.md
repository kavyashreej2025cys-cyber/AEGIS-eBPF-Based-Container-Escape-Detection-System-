# AEGIS Escape
## Container Escape Attack Detection via Real-Time eBPF Telemetry and Deep Behavioral Autoencoders

A complete runnable **research prototype**: host-side eBPF collector → authenticated HTTP ingest → per-container behavioral windows → deep autoencoder + sensitive-operation rules → SQLite → live dashboard → analyst acknowledgement/export.

**Start here:** Windows/Linux demo needs only Python 3.10+ and NumPy. The included trained model is a **synthetic demonstration model**, not a validated production detector. Real collection needs a Linux container host. Read `docs/LINUX_SETUP.md` before live mode.

## Quick start — Windows

1. Install Python 3.10 or newer (select “Add Python to PATH”).
2. Extract this ZIP, open `aegis-escape`, then double-click `scripts/start-demo.bat`.
3. Open **http://127.0.0.1:8080** in a browser. Keep the terminal open.
4. Select “Namespace change attempt” and click **Generate demo telemetry**. Wait up to six seconds.
5. Inspect rule evidence, reconstruction-error features and telemetry; acknowledge the alert or export it.

If double-click does not work, open a terminal in this folder:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m aegis.server --mode demo
```

No activation of PowerShell scripts is required. Demo action token: `demo-local-token`. Synthetic scenarios do not execute attacks. First install requires internet for NumPy; the dashboard has no CDN/external runtime dependency.

## Quick start — Linux / macOS demo

```bash
bash scripts/start-demo.sh
```

Or create a virtual environment, install `requirements.txt`, and run `python -m aegis.server --mode demo`. Stop with Ctrl+C. Do not run the web server as root.

## Included capabilities

- BCC eBPF entry/exit tracing for 14 supported syscall families; cgroup v2 ID, PID/TID, UID, process name, selected pathname, return and duration.
- Host-side Docker/containerd/CRI-O container ID resolution from `/proc/<pid>/cgroup`; explicit cgroup selection fallback.
- Bounded ingestion queues, perf-buffer loss counter, collector heartbeat and visible missing-probe coverage.
- Twenty log-count features per five-second container/source window.
- Dense deep autoencoder **20 → 32 → 16 → 4 → 16 → 32 → 20**, tanh hidden layers, linear reconstruction, MSE, NumPy backpropagation and Adam.
- Normal-only training, independent calibration and held-out benign testing; 99th-percentile validation threshold.
- Hybrid rules for sensitive syscalls and selected resource paths; successful vs failed syscall outcomes.
- Two-second dashboard refresh, active container cards, score chart, evidence, acknowledgements and JSONL export.
- SQLite WAL persistence and seven-day application retention; portable pretrained model without pickle.
- CLI training, safe synthetic evaluation, record/replay, unit and HTTP integration tests, Linux Docker demo packaging.

## Train / evaluate

```bash
python -m aegis.train --epochs 100 --output models
python scripts/evaluate.py
python -m unittest discover -s tests -v
```

Training without `--input` uses synthetic data. For a real baseline, collect **trusted benign workload** windows separately, then:

```bash
python -m aegis.train --input data/benign.jsonl --output models-real --window 5 --epochs 150
python -m aegis.server --mode live --models models-real --data data-live
```

Set `AEGIS_TOKEN` before live mode. Restart the service after retraining; model hot reload is intentionally absent. At least 100 nonempty windows are required; collect substantially more across normal workload variations. Do not use the provided synthetic capture as a real baseline. Do not retrain automatically on suspicious traffic.

## Linux Docker demo (optional)

```bash
docker compose up --build
```

Open `http://127.0.0.1:8080`. Compose uses **Linux host networking**, not portable Windows Docker Desktop networking. Windows users should use the native Python demo or the Ubuntu VM instructions. This container runs the demo server only; real collector runs on the host. Persistent volume: `aegis-data`. `docker compose down` stops it; adding `-v` deletes saved demo data.

## Folder map

| Path | Purpose |
| --- | --- |
| `aegis/` | Features, NumPy model, training, engine, SQLite, HTTP service |
| `collector/collect.py` | Linux BCC eBPF collector and authenticated delivery |
| `dashboard/index.html` | Offline HTML/CSS/JavaScript dashboard |
| `models/` | Included trained synthetic model, provenance and metrics |
| `data/sample-demo.jsonl` | Replayable synthetic scenario examples |
| `scripts/` | Launchers, replay and evaluation |
| `tests/` | Model, engine, API and collector-generation checks |
| `docs/` | Linux/Windows guides, API, architecture, research report, validation |

## Important interpretation

This detects **escape-related indicators and behavior anomalies**, not guaranteed successful escapes. Syscall success can be benign; a failed action can still be suspicious. No automatic blocking, kernel exploit payloads, or escape tooling is included. Rules can alert on legitimate administrative operations. The synthetic metrics do not establish effectiveness against real attacks. See `docs/LIMITATIONS.md` for coverage and deployment constraints.
