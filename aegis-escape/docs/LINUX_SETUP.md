# Live eBPF setup — Ubuntu Linux host

## Why Linux?

eBPF attaches to Linux kernel tracepoints. Windows can run the NumPy model, dashboard and demo, but native Windows cannot run this BCC collector. The collector must run on the **same Linux kernel that hosts the monitored containers**. Monitoring inside an unrelated VM does not observe Windows-hosted processes/containers.

## Recommended test environment

Ubuntu 24.04 LTS VM or dedicated Linux machine, 4 virtual CPUs, 4–8 GB RAM, 15 GB free disk. These are development starting points, not measured production sizing. Use a recent cgroup v2 kernel and a Docker host. A GPU is unnecessary for this model. For Windows VM networking and setup, see `WINDOWS_SETUP.md`.

## Install host prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-numpy python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
```

Install Docker Engine using the official Ubuntu instructions: https://docs.docker.com/engine/install/ubuntu/
Verify:

```bash
uname -r
test -f /sys/fs/cgroup/cgroup.controllers && echo 'cgroup v2 OK'
sudo /usr/bin/python3 -c 'from bcc import BPF; print("BCC import OK")'
sudo ls /sys/kernel/tracing/events/syscalls
```

If tracefs is absent, mount it:

```bash
sudo mkdir -p /sys/kernel/tracing
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

A lockdown policy, missing tracepoints, missing kernel headers or unavailable BPF privileges can prevent attachment. Collector prints successfully included probes and omitted syscall families. Syscall entry + exit are both required per family. Fix kernel support rather than treating partial coverage as full coverage.

## Start server (unprivileged)

From the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export AEGIS_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
.venv/bin/python -m aegis.server --mode live --data data-live
```

Record your generated token privately. In a second terminal set **the same** `AEGIS_TOKEN`, then run:

```bash
sudo -E /usr/bin/python3 collector/collect.py --output data/live-capture.jsonl
```

The collector uses system Python because Ubuntu's `python3-bpfcc` is a distribution package. `python3-numpy` is required because the shared feature schema imports NumPy. Do not `pip install bcc`: that name can resolve to an unrelated package. Keep the HTTP server unprivileged.

## Generate harmless real container traffic

In a third terminal:

```bash
sudo docker run --rm --name aegis-benign python:3.12-slim python -c 'import time,pathlib; [(pathlib.Path("/tmp/aegis-benign").write_text(str(i)),time.sleep(0.2)) for i in range(100)]'
```

Open http://127.0.0.1:8080 on the Linux host. Use your token for acknowledgement. Expect real `openat` activity; this workload does not attempt an escape. The demo injection button is disabled in live mode. Anomalies with the synthetic model are expected and **not evidence of an attack**.

## Collect trusted baseline data

Run representative applications for at least ten minutes and preferably hours, across normal request rates, restarts and maintenance. Write a separate capture, e.g. `data/benign.jsonl`. Stop collector, review the capture and confirm it contains only trusted normal activity. Train as described in README. Restart server with `--models models-real`; then restart the collector using the same token.

## Explicit cgroup fallback

Default resolution recognises 64-character Docker/containerd/CRI-O IDs in `/proc/<pid>/cgroup`. If your runtime uses a different layout, inspect the target container's host PID and cgroup path:

```bash
sudo docker inspect -f '{{.State.Pid}}' aegis-benign
sudo cat /proc/REPLACE_HOST_PID/cgroup
```

Locate the `0::/...` cgroup v2 path beneath `/sys/fs/cgroup`. Get its inode/ID:

```bash
sudo stat -c '%i' /sys/fs/cgroup/REPLACE_CGROUP_PATH
sudo -E /usr/bin/python3 collector/collect.py --cgroup-id REPLACE_ID
```

Replace placeholders with observed values. The option may repeat. Container IDs become `cgroup-ID`. Host events are otherwise skipped. Short-lived processes can disappear before `/proc` resolution; once resolved, subsequent events for the same cgroup use the cache. See limitations for the observation gap.

## Stop / cleanup

Ctrl+C the collector and server. Collector does not block syscalls or change runtime configuration. Database is local to `data-live/`. Captures append and need operator rotation; preserve files needed for research before deleting.
