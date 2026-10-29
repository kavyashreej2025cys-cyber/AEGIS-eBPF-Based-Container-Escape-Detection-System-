# API reference

Base URL: `http://127.0.0.1:8080`. JSON responses except `/` and `/api/export`.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Service liveness and mode |
| GET | `/api/status` | Model metadata, active containers, counters and heartbeat |
| GET | `/api/events` | Latest 100 raw events |
| GET | `/api/windows` | Latest 100 scored behavioral windows |
| GET | `/api/alerts` | Latest 100 alerts including acknowledgement |
| GET | `/api/export` | Latest 1,000 alerts, chronological NDJSON |
| POST | `/api/ingest` | Batch of 1–500 events; returns accepted/errors/dropped |
| POST | `/api/collector` | Collector heartbeat and loss/coverage counters |
| POST | `/api/demo` | Synthetic scenario injection, demo mode only |
| POST | `/api/ack` | Acknowledge persisted alert ID |

POST requires `Authorization: Bearer <AEGIS_TOKEN>`. Default demo token is `demo-local-token`. Live requires a token. Max body 1 MiB. Per-event errors are returned without discarding valid events in the batch. HTTP status 200 is not a guarantee of full acceptance: inspect `accepted`, `errors`, `dropped`. Sources must match service mode.

Example ingest body (replace ts with current Unix time):

```json
{"events":[{"ts":1791240000,"container_id":"demo-web","cgroup_id":1001,"pid":201,"uid":1000,"comm":"python3","syscall":"openat","path":"/app/config.json","ret":3,"source":"demo"}]}
```

Required event fields: `ts`, `container_id`, `pid`, `syscall`, `source`. Optional: `uid`, `ret`, `cgroup_id`, `tid`, `path`, `comm`, `duration_ns`. Collector supplies all fields. Supported syscalls are listed in `aegis/features.py`. Timestamps must be within 60 seconds past / 5 seconds future. Replay refreshes timestamps. Receive time assigns windows; collector timestamps report reception from perf buffer, not Unix time from inside the kernel.

Demo: `{"scenario":"namespace"}`. Also `normal`, `runtime-socket`, `mount-probe`, `unknown-burst`. Acknowledge: `{"id":1}`. Collector heartbeat: `{"lost":0,"queue_dropped":0,"delivery_errors":0,"skipped":0,"probes":["openat"]}`.

Read routes are unauthenticated because server binds only to loopback. For remote access, use SSH forwarding; do not expose this research server directly to a network. There is no user account management or TLS terminator in this project.
