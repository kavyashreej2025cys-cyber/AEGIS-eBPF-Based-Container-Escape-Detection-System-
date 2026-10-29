# Project report

**Title:** Container Escape Attack Detection via Real-Time eBPF Telemetry and Deep Behavioral Autoencoders

## Problem

Container isolation shares the host kernel. Escape-related activity can include namespace transitions, runtime-socket access or attempts to reach privileged resources. Signature-only approaches may miss unusual behavior; anomaly-only approaches can confuse legitimate change with malicious intent. A detector needs observable evidence and transparent provenance.

## Objective

Implement a host-side telemetry-to-alert pipeline that aggregates each container's behavior, learns a trusted normal baseline, and combines reconstruction anomalies with sensitive-operation rules for analyst review.

## Method

BCC probes on syscall entry/exit produce cgroup and process context with return status. A bounded userspace relay forwards authenticated events to a local HTTP service. Per-container windows are transformed into 20 log-count features. A six-layer dense autoencoder compresses behavior to a four-dimensional bottleneck and reconstructs it. High reconstruction error indicates departure from the training distribution. Normal calibration windows establish a percentile threshold. Rules provide complementary evidence for selected risky operations. SQLite and a dashboard support review, persistence and export.

## Demonstration

Start demo mode on Windows/Linux. Present normal telemetry first, then namespace-attempt, runtime-socket, mount/chroot and unknown-burst scenarios. All are synthetic event generation. Show high-level alert, failed/successful return outcomes, contributing features, source provenance and acknowledgement. Live demonstration should use harmless Linux container traffic to prove real collector integration. Validate escape detection separately in an authorised isolated lab; no exploit programs are provided here.

## Evaluation design

Report held-out benign false-positive rate and reconstruction loss. Synthetic scenario detection demonstrates pipeline responsiveness only. Real validation should use isolated labelled workload runs with train/test separation by run, container and time, a diversity of legitimate workloads, and authorised attack traces. Measure precision, recall, F1, false alerts/hour, latency, telemetry loss and CPU/memory overhead. Compare rule-only, autoencoder-only and hybrid outputs. Report unsupported probe coverage and missed-event attribution gaps. Do not invent real-world accuracy from synthetic examples.

## Deliverables

Source code, trained synthetic model, reproducible training and evaluation, sample replay telemetry, live collector, browser dashboard, local database, tests, Linux/Windows guides and API documentation.

## Future work

Resolve full filesystem paths, capture Unix connect addresses and namespace identifiers, add openat2/execveat/LSM coverage, enrich Kubernetes identities, compare sequence autoencoders, calibrate per workload, benchmark real overhead and add secure cluster deployment.

## Primary references

- BCC reference guide: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
- BCC installation instructions: https://github.com/iovisor/bcc/blob/master/INSTALL.md
- Linux BPF helper definitions: https://github.com/torvalds/linux/blob/master/kernel/bpf/helpers.c
- Linux cgroup v2 documentation: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
- Docker Ubuntu installation: https://docs.docker.com/engine/install/ubuntu/

The included model uses NumPy, not PyTorch. This implementation is a project prototype, not a claim of a new validated research algorithm.
