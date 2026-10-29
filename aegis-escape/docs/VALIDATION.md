# Validation performed

- Eight automated tests passed using `python -m unittest discover -s tests -v`.
- Model training reduces reconstruction loss and save/load preserves predictions.
- Tests cover feature extraction, failed-attempt evidence, per-container/source window isolation, backpressure, acknowledgement persistence, HTTP authentication, invalid events, source enforcement, cross-origin write rejection and live-mode demo rejection.
- Actual subprocess HTTP smoke check verified startup, synthetic scenario injection, automatic window scoring, persisted hybrid alerts and three active demo containers.
- Python sources compiled with compileall; dashboard JavaScript passed `node --check`.
- Synthetic evaluation used 500 unseen normal windows: 2.2% anomaly false-positive rate. Each of four synthetic abnormal scenarios scored above threshold for all 100 generated examples. Unknown-burst had no rule hit and was detected by autoencoder. These are synthetic smoke metrics, not real attack performance.
- Included model's training metadata separately records its held-out synthetic split: 270 normal windows and 3.70% anomaly false-positive rate. Different independent samples produce different rates.

Not performed: live Linux BCC kernel attachment, Windows machine execution, Docker image build, graphical browser screenshot/interaction, real container escape validation or production performance benchmarks. The runnable demo was tested on Linux Python; Windows launcher is provided for the same portable code path.
