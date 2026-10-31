# From Benign Flows to Labeled Attacks

Code for generating labeled attack flow records for a production network (AmLight) from benign traffic statistics and an attack description, using open-weight LLMs (Llama 3.1 8B, Falcon3 10B, Qwen2.5 7B) served with Ollama on FABRIC. Case study: TCP ACK flood. Submitted to IEEE ICC 2027.

## Data

Files in `data/` (all IP addresses anonymized as `anon_ip_N`). Upload them to `/content/` in Colab before running the notebooks.

| File | Rows | Contents |
|---|---|---|
| `focused_anon_labeled_04_04_2026.csv` | 5,060 | original labeled capture, with the extra label columns `attack_type`, `attack_subtype`, `attack_phase` |
| `Final Data.csv` | 5,060 | the same flows with the 113 columns used in this work |
| `train.csv` | 3,520 | 404 benign + 3,116 attack |
| `test.csv` | 1,540 | 194 benign + 1,346 attack |

 The split is grouped by `flow_key`: every record of a flow stays on the same side, so no flow appears in both train and test. `GroupShuffleSplit(test_size=0.30)` assigns 30% of the flow-key *groups* (not rows) to the test set, separately for benign and attack. Because groups differ in size, row counts are close to but not exactly 70/30: 404 / 194 benign (67.6% / 32.4%) and 3,116 / 1,346 attack (69.8% / 30.2%).

`benign.csv` (all 598 benign flows) is created by notebook 01.

`Final Data.csv`: 5,060 labeled flows (598 benign, 4,462 attack), 112 features + `is_attack`.

Split (notebook 01): 70/30 per class with `GroupShuffleSplit`, grouped by `flow_key`, seed 42.
- `train.csv`: 404 benign + 3,116 attack
- `test.csv`: 194 benign + 1,346 attack
- `benign.csv`: all 598 benign flows (used for the Setting A prompt statistics)

Note: the Setting A benign statistics (`rules.json`) are computed from all 598 benign flows, including the 194 test benign flows. Detectors are trained only on the 404 training benign flows. Target-side window statistics use only the 152 benign flows from attack-free timeframes (1-4, 12-13).

## Pipeline (run in order, Google Colab)

| Notebook | Produces |
|---|---|
| `01_split_and_settingA_rules_prompt` | `train.csv`, `test.csv`, `benign.csv`, `rules.json`, `prompt_attack.txt` (Setting A), `generation_order.json` |
| `02_settingB_attack_rules` | `rules_attack.json`, `attack_stats_section.txt` (Setting B, from the 3,116 training attacks only) |
| `03_settingB_real_examples` | the 10 real training attack flows added to the Setting B prompt (seed 2026) |
| `04_heuristic_baseline` | `heuristic_attack_N3300_seed42.csv` (same inputs as Setting A) |
| `05_tstr_f1_ba_and_ctgan_k2000` | Table II (TSTR F1 and balanced accuracy, RF/LR/SVM, 85 features) and CTGAN k = 2,000 (300 epochs, seeds 42/45/50) with fidelity |
| `06_settingA_confusion_counts` | Setting A confusion counts (false positives on 194 benign test flows) |
| `07_benign_only_anomaly_baseline` | Isolation Forest / One-Class SVM trained on the 404 benign training flows |
| `08_fusion_and_exploration` | fusion of the three LLMs (`fuse_run`); also contains earlier exploratory cells (MLP, run-3, voting, medoid) not used in the paper |
| `extra/` | CTGAN epoch/seed sensitivity and data-efficiency checks (supporting only) |

## Generation (FABRIC, `generation/`)

| File | Purpose |
|---|---|
| `gen_attack.py` | driver: one call per flow, JSON schema forcing all 113 keys and types (not values), exact-duplicate removal, per-call seed = `SEED_BASE` + call number |
| `generation_order.json` | the 113 columns in generation order |
| `prompts/settingA_benign_stats.txt` | Setting A prompt (built by notebook 01) |
| `prompts/description_only.txt` | description-only baseline: Setting A without the benign statistics (built by `build_prompt_desc_only.py`, run with `SEED_BASE=300000`) |
| `prompts/settingB_attack_stats_10_flows.txt` | Setting B prompt (attack statistics from notebook 02 + 10 real flows from notebook 03) |
| `fabric_run_falcon.ipynb` | slice setup on an A30, Ollama 0.34.4 install, smoke test (K = 1, 5, 10) and full run; the other models use the same notebook with `MODEL` changed |

The driver reads `prompts/prompt_attack.txt`; copy the prompt of the setting you want to that name on the node. Runs used:

```
MODEL=falcon3:10b K=1 TARGET_ROWS=3300 NUM_PREDICT=3000 SEED_BASE=0      TAG=falcon_run1 python3 gen_attack.py
MODEL=falcon3:10b K=1 TARGET_ROWS=3300 NUM_PREDICT=3000 SEED_BASE=100000 TAG=falcon_run2 python3 gen_attack.py
```

Models: `llama3.1:8b`, `falcon3:10b`, `qwen2.5:7b`. Defaults: temperature 0.8, top-p 0.95, `num_ctx` 24,576.

## Evaluation setup

- Detectors: RandomForest (300 trees), LogisticRegression, LinearSVC; `class_weight='balanced'`, seed 42; `SimpleImputer(0)` + `StandardScaler`.
- Features: 85 of 112, after removing 6 identifier columns (`flow_key`, `timeframe_id`, `ip_a`, `ip_b`, `port_a`, `port_b`) and 21 window-level columns (`source_*`, `target_*`, `flow_share_*`).
- Training: synthetic attack flows + the 404 real benign training flows. Test: the fixed 1,540-flow test set.
- Fidelity: KS and JSD (20 quantile bins) averaged over features; MMD² with a multi-bandwidth RBF kernel on quantile-transformed features, 1,000-row subsamples, against the 1,346 real test attacks.

## Requirements

See `requirements.txt`. CTGAN uses `sdv<2` (SDV 2.0 changed the API used here).
