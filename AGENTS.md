# AGENTS.md

This is a data-science project, not a software repo. There is **no build system, test suite, linter, CI, or lockfile**. Do not look for `pytest`, `Makefile`, `package.json`, etc.

## Structure

- `Network Intusion Detection Systems/` — the only code. Contains `NIDS.ipynb` (the entrypoint), `requirements.txt`, and the KDD Cup 1999 dataset.
- `Edge-IIoTset dataset/` — separate IIoT traffic dataset (Attack / Normal traffic, Selected dataset for ML and DL). Not wired into `NIDS.ipynb`.
- `Proposal_Report_2.pdf`, `Agume Kenneth_Poster.jpg` — report assets, not code.

## Run the notebook

1. `cd "Network Intusion Detection Systems"` (paths contain spaces — quote them).
2. `pip install -r requirements.txt` — installs `jupyter pandas numpy matplotlib seaborn scikit-learn xgboost tensorflow`.
3. `jupyter notebook NIDS.ipynb` and run all cells.

## Notebook behavior to know

- `NIDS.ipynb` reads `KDDCup Data 10 Percent.csv` with no header, then derives column names by parsing `kddcup.txt` (sliced at byte offset 182) and writes `KDDCup Data 10 Percent (Edited).csv`. Keep all three files in that folder together.
- Relative paths are used throughout, so the notebook must be run from `Network Intusion Detection Systems/`, not the repo root.
- `requirements.txt` lists `tensorflow`; the notebook itself imports scikit-learn/xgboost classifiers (Decision Tree, Random Forest, AdaBoost, XGBoost, Gradient Boosting, HistGradientBoosting) — no TensorFlow code is actually used in the notebook.

## Results (from README, for reference only)

Random Forest 99.76% > Decision Tree 99.59% > KNN 99.41% > XGBoost 99.39% > AdaBoost 94.54% > HistGradientBoosting 93.10% > GradientBoosting 92.86%.

## Nothing else to configure

No `opencode.json`, no pre-commit, no codegen, no migrations, no env files. If you're asked to add tests/lint/CI, that's a new scope decision — none exists today.
