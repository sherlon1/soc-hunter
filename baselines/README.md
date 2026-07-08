# Baselines

Versioned behavior baselines created by `scripts/baseline-manager.py`.

Each baseline is stored as `B-XXXX.json` and tracks normal behavior statistics
(mean ± stddev per entity/metric) so deviations can be sigma-scored in future
comparison runs.

Files in this directory are generated at runtime and excluded from version control.
