# Scope and known limitations

- **Live BCC attachment has not been validated in the build environment.** Test on the target Ubuntu kernel. Source compiles as Python; generated probe structure is tested, but that is not a kernel verifier test.
- The included model is trained on synthetic unprivileged Python-like workloads. Synthetic detection results cannot be extrapolated to real escapes, CVEs or production false-positive rates.
- This is a deep dense window autoencoder, not an LSTM or sequence model. It aggregates order away. It does not model every syscall or arbitrary kernel memory corruption.
- Partial syscall coverage varies with kernel tracepoints. `openat2`, `execveat`, io_uring, kernel module loading, credentials changes and LSM hooks are not included.
- Path capture is capped at 191 bytes. Relative paths and dirfd-based access are not resolved. Symlinks and bind mounts can hide true resources. Sensitive-path rules are heuristic: `/proc/1` inside a container may refer to its own namespace's PID 1, not the host.
- Runtime-socket detection uses observed `openat` path strings. Unix socket `connect()` addresses are not captured, so direct socket connects can be missed. Network addresses, network payloads and syscall arguments such as namespace flags are not extracted.
- Successful syscall returns do not establish an escape or host namespace membership. No host/container namespace comparison or confirmed escape label is provided.
- Userspace `/proc` attribution races with short-lived process exit. Unresolved events are skipped. Runtime cgroup layouts without recognised IDs require explicit cgroup filtering. Kubernetes support is limited to matching underlying runtime cgroups; no pod/namespace enrichment is implemented.
- No trusted normal capture automatically validates benignness. Operator must review baseline data; poisoning and workload drift affect reconstruction detectors. Missing probes should trigger baseline recollection/retraining.
- Per-container rates differ; the shared baseline can over-alert on legitimate root or administrative workloads. Rules always fire on designated sensitive operations; acknowledgements do not retrain or suppress them.
- Perf and queue loss, HTTP expiry, window caps and thread/database contention can reduce visibility under load. There is no kernel-side rate limiter or performance benchmark included. Capture files append indefinitely unless rotated manually.
- HTTP is a loopback-only development service; reads are unauthenticated. Token authenticates writes, not encryption. Do not expose it publicly. For a deployed product add TLS, RBAC, audit identity, event integrity, rate limiting, resource quotas and resilient transport.
- Demo/ebpf modes do not accept mixed sources. Persisted databases can contain previous mode records if reused; use separate `--data` directories.
