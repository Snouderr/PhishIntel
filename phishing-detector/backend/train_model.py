"""
Train, compare and evaluate phishing URL classifiers — v2 (Phase 4).

What changed from v1, and why (each point is a fix for an evaluation flaw):

  * Group-aware splits. URLs are grouped by registered domain (or by host on
    shared platforms like github.io / shorteners), and a group never appears
    in both train and test. A random split lets the model memorise domains
    and inflates every score.
  * No list-membership features in the model. `is_trusted_domain` was built
    from the same Tranco list the legitimate URLs came from (label leakage);
    it now lives only in the API's rule layer.
  * Realistic legitimate URLs. data/urls_v2.csv (build_dataset.py) adds real
    deep links and legitimate pages on free-hosting platforms, so "has a
    path" or "is on weebly" stop being shortcuts.
  * Model selection by 5-fold group CV on the training set only; the test
    set is touched once, at the end.
  * Calibrated probabilities (sigmoid) + a decision threshold chosen on
    cross-validated predictions to keep precision >= 97% (few false alarms).

Outputs (reports/):
  metrics.json             all numbers, incl. the old model on the same test set
  model_comparison.csv     CV results per model
  confusion_matrix.png, roc_pr_curves.png, feature_importance.png
  errors_false_positives.csv / errors_false_negatives.csv   for error analysis
And backend/model.pkl — a bundle {model, features, threshold, reference, metrics}.

Usage:
    python train_model.py                 # uses data/urls_v2.csv if present
    python train_model.py --data ../data/urls.csv
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.calibration import CalibratedClassifierCV  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier  # noqa: E402
from sklearn.inspection import permutation_importance  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score, average_precision_score, confusion_matrix, f1_score,
    precision_recall_curve, precision_score, recall_score, roc_auc_score, roc_curve,
)
from sklearn.model_selection import (  # noqa: E402
    GroupShuffleSplit, StratifiedGroupKFold, cross_val_predict,
)
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from brands import FREE_HOSTING_PLATFORMS  # noqa: E402
from feature_extraction import (  # noqa: E402
    NON_MODEL_FEATURES, SHORTENER_DOMAINS, extract_features, get_full_domain,
)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "data")
REPORTS = os.path.join(HERE, "..", "reports")
MODEL_PATH = os.path.join(HERE, "model.pkl")
LEGACY_FILES = [os.path.join(HERE, f) for f in ("scaler.pkl", "model_features.pkl")]
SEED = 42
# False alarms are what make people uninstall a security extension, so the
# threshold must keep precision at or above this on cross-validated predictions.
MIN_PRECISION = 0.97
MODEL_VERSION = "2.0"


def group_key(url: str) -> str:
    """Registered domain — except on shared platforms, where each host is its own owner."""
    reg = get_full_domain(url)
    if reg in FREE_HOSTING_PLATFORMS or reg in SHORTENER_DOMAINS or reg == "google.com":
        host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].lower()
        return host
    return reg


def featurize(urls) -> pd.DataFrame:
    t = time.time()
    rows = [extract_features(str(u)) for u in urls]
    print(f"  featurised {len(rows)} URLs in {time.time() - t:.1f}s")
    return pd.DataFrame(rows)


def candidate_models() -> dict:
    return {
        "Logistic Regression": Pipeline([("scale", StandardScaler()),
                                         ("clf", LogisticRegression(max_iter=3000, C=1.0))]),
        "Random Forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                                n_jobs=-1, random_state=SEED),
        "Hist Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=400, learning_rate=0.08, max_leaf_nodes=31, l2_regularization=1.0,
            random_state=SEED),
    }


def single_threaded(model):
    """Parallel trees help when training, but for one URL at a time the
    thread start-up costs more than the prediction (~10x slower)."""
    for cc in getattr(model, "calibrated_classifiers_", []):
        est = cc.estimator
        if hasattr(est, "n_jobs"):
            est.n_jobs = 1
    return model


def scores(y, proba, threshold=0.5) -> dict:
    pred = proba >= threshold
    return {
        "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred), "f1": f1_score(y, pred),
        "roc_auc": roc_auc_score(y, proba), "pr_auc": average_precision_score(y, proba),
        "false_positive_rate": float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)),
    }


def best_threshold(y, proba, min_precision=MIN_PRECISION) -> float:
    """Highest-F1 threshold among those meeting a precision floor (false alarms
    in a browser extension are costly), falling back to plain best F1."""
    p, r, t = precision_recall_curve(y, proba)
    f1 = 2 * p[:-1] * r[:-1] / np.clip(p[:-1] + r[:-1], 1e-9, None)
    ok = p[:-1] >= min_precision
    idx = int(np.argmax(np.where(ok, f1, -1))) if ok.any() else int(np.argmax(f1))
    return float(t[idx])


LEGACY_DIR = os.path.join(HERE, "legacy_v1")


def legacy_proba(X: pd.DataFrame):
    """The original v1 model (kept in legacy_v1/) on the same test rows, so
    every retrain reports an honest before/after comparison."""
    try:
        model = joblib.load(os.path.join(LEGACY_DIR, "model.pkl"))
        cols = joblib.load(os.path.join(LEGACY_DIR, "model_features.pkl"))
        scaler = joblib.load(os.path.join(LEGACY_DIR, "scaler.pkl"))
        return model.predict_proba(scaler.transform(X[cols]))[:, 1]
    except (FileNotFoundError, KeyError, ValueError):
        return None


def plot_curves(y, curves: dict, path, subset="held-out test set"):
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.5))
    for name, proba in curves.items():
        fpr, tpr, _ = roc_curve(y, proba)
        p, r, _ = precision_recall_curve(y, proba)
        a1.plot(fpr, tpr, label=f"{name} (AUC {roc_auc_score(y, proba):.3f})")
        a2.plot(r, p, label=f"{name} (AP {average_precision_score(y, proba):.3f})")
    a1.plot([0, 1], [0, 1], "--", color="#bbb")
    a1.set(xlabel="False positive rate", ylabel="True positive rate", title=f"ROC — {subset}")
    a2.set(xlabel="Recall", ylabel="Precision", title=f"Precision–Recall — {subset}")
    for a in (a1, a2):
        a.legend(loc="lower right", fontsize=8)
        a.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_confusion(cm, path, title):
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, f"{v:,}", ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black", fontsize=12)
    ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["legit", "phishing"],
           yticklabels=["legit", "phishing"], xlabel="Predicted", ylabel="Actual", title=title)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_importance(imp: pd.Series, path):
    imp = imp.sort_values().tail(20)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.barh(imp.index, imp.values, color="#3b6fb6")
    ax.set(xlabel="Drop in PR-AUC when the feature is shuffled",
           title="Permutation feature importance (test set)")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    default = os.path.join(DATA_DIR, "urls_v2.csv")
    if not os.path.exists(default):
        default = os.path.join(DATA_DIR, "urls.csv")
    ap.add_argument("--data", default=default)
    ap.add_argument("--model-out", default=MODEL_PATH)
    ap.add_argument("--reports", default=REPORTS)
    args = ap.parse_args()
    reports = args.reports
    os.makedirs(reports, exist_ok=True)

    df = pd.read_csv(args.data).drop_duplicates("url").reset_index(drop=True)
    if "source" not in df.columns:
        df["source"] = "unknown"
    print(f"Data: {args.data}\n  {len(df)} URLs — {int(df.label.sum())} phishing / {int((df.label == 0).sum())} legit")

    X_all = featurize(df.url)
    feature_cols = [c for c in X_all.columns if c not in NON_MODEL_FEATURES]
    X = X_all[feature_cols]
    y = df.label.values
    groups = df.url.map(group_key).values
    print(f"  {len(feature_cols)} model features, {len(set(groups))} domain groups")

    # Held-out test set: whole domains, never seen during training/selection
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
    Xtr, ytr, gtr = X.iloc[tr], y[tr], groups[tr]
    Xte, yte = X.iloc[te], y[te]
    print(f"  train {len(tr)} / test {len(te)} (no shared domains)")

    # ── model selection: 5-fold group CV on train ──
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    results, oof = [], {}
    for name, est in candidate_models().items():
        t = time.time()
        proba = cross_val_predict(est, Xtr, ytr, groups=gtr, cv=cv, method="predict_proba", n_jobs=1)[:, 1]
        oof[name] = proba
        results.append({"model": name, **scores(ytr, proba), "seconds": round(time.time() - t, 1)})
        print(f"  CV {name:24s} F1 {results[-1]['f1']:.3f}  PR-AUC {results[-1]['pr_auc']:.3f}")
    comp = pd.DataFrame(results).sort_values("pr_auc", ascending=False)
    comp.to_csv(os.path.join(reports, "model_comparison.csv"), index=False)
    best_name = comp.iloc[0]["model"]
    print(f"Best by CV PR-AUC: {best_name}")

    # ── decision threshold from out-of-fold predictions of the *calibrated*
    # model over all of train (5 group folds) — a single validation split
    # proved too noisy (one data change moved it from 0.79 to 0.42) ──
    # ensemble=False: one model fitted on all rows + a sigmoid fitted on CV
    # predictions — same calibration quality, 5x faster to serve than 5 copies
    calib = CalibratedClassifierCV(candidate_models()[best_name], method="sigmoid", cv=5, ensemble=False)
    oof_cal = cross_val_predict(calib, Xtr, ytr, groups=gtr, cv=cv, method="predict_proba", n_jobs=1)[:, 1]
    threshold = best_threshold(ytr, oof_cal, MIN_PRECISION)
    print(f"  decision threshold (CV precision >= {MIN_PRECISION}): {threshold:.3f}")

    final = CalibratedClassifierCV(candidate_models()[best_name], method="sigmoid", cv=5, ensemble=False)
    final.fit(Xtr, ytr)
    single_threaded(final)

    # ── held-out test ──
    p_new = final.predict_proba(Xte)[:, 1]
    test = scores(yte, p_new, threshold)
    print("\nTest set (unseen domains):", json.dumps({k: round(v, 4) for k, v in test.items()}))

    curves = {f"v2 {best_name}": p_new}
    curve_y = yte
    curve_subset = "held-out test set"
    p_old = legacy_proba(X_all.iloc[te])
    legacy = None
    if p_old is not None:
        # The v1 model was trained on data/urls.csv, so test rows taken from
        # that file are ones it has already seen. The fair head-to-head is on
        # the rows neither model trained on.
        v1_train = os.path.join(DATA_DIR, "urls.csv")
        seen = set(pd.read_csv(v1_train).url) if os.path.exists(v1_train) else set()
        unseen = ~df.url.iloc[te].isin(seen).values
        legacy = {"all_test_rows": scores(yte, p_old, 0.5)}
        if unseen.sum() and len(set(yte[unseen])) == 2:
            legacy["unseen_by_v1"] = {"n": int(unseen.sum()), **scores(yte[unseen], p_old[unseen], 0.5)}
            legacy["v2_on_same_rows"] = scores(yte[unseen], p_new[unseen], threshold)
            curves = {"v1 (old model)": p_old[unseen], f"v2 {best_name}": p_new[unseen]}
            curve_y = yte[unseen]
            curve_subset = f"test URLs unseen by v1 (n={int(unseen.sum())})"
            print(f"Rows unseen by v1 ({unseen.sum()}):")
            print("  v1:", json.dumps({k: round(v, 4) for k, v in legacy["unseen_by_v1"].items()}))
            print("  v2:", json.dumps({k: round(v, 4) for k, v in legacy["v2_on_same_rows"].items()}))

    # Per-source breakdown — where does the model still struggle?
    src = df.source.values[te]
    pred = p_new >= threshold
    by_source = {s: {"n": int((src == s).sum()), "accuracy": round(float((pred[src == s] == yte[src == s]).mean()), 4)}
                 for s in sorted(set(src))}
    if p_old is not None:
        old_pred = p_old >= 0.5
        for s in by_source:
            by_source[s]["accuracy_v1"] = round(float((old_pred[src == s] == yte[src == s]).mean()), 4)
    print("Accuracy by source:", json.dumps(by_source))

    # ── figures + error analysis ──
    plot_curves(curve_y, curves, os.path.join(reports, "roc_pr_curves.png"), curve_subset)
    plot_confusion(confusion_matrix(yte, pred), os.path.join(reports, "confusion_matrix.png"),
                   f"v2 {best_name}\n(threshold {threshold:.2f})")
    print("  computing permutation importance…")
    pi = permutation_importance(final, Xte, yte, scoring="average_precision", n_repeats=5,
                                random_state=SEED, n_jobs=1)
    importance = pd.Series(pi.importances_mean, index=feature_cols)
    plot_importance(importance, os.path.join(reports, "feature_importance.png"))

    errs = df.iloc[te].assign(proba=p_new.round(4), predicted=pred.astype(int))
    errs[(errs.label == 0) & (errs.predicted == 1)].sort_values("proba", ascending=False) \
        .to_csv(os.path.join(reports, "errors_false_positives.csv"), index=False)
    errs[(errs.label == 1) & (errs.predicted == 0)].sort_values("proba") \
        .to_csv(os.path.join(reports, "errors_false_negatives.csv"), index=False)

    metrics = {
        "model_version": MODEL_VERSION, "model": best_name,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data": os.path.basename(args.data), "rows": len(df),
        "train_rows": len(tr), "test_rows": len(te), "threshold": threshold,
        "features": feature_cols, "cv": comp.to_dict(orient="records"),
        "test": test, "test_v1_old_model": legacy, "test_by_source": by_source,
        "feature_importance": importance.sort_values(ascending=False).round(5).to_dict(),
    }
    with open(os.path.join(reports, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Reference row for explanations: the typical legitimate URL
    reference = X[y == 0].median().to_dict()
    joblib.dump({"model": final, "features": feature_cols, "threshold": threshold,
                 "reference": reference, "version": MODEL_VERSION, "model_name": best_name,
                 "metrics": {"test": test, "trained_at": metrics["trained_at"]}},
                args.model_out, compress=3)  # ~45 MB -> ~10 MB for a 300-tree forest
    if os.path.abspath(args.model_out) == os.path.abspath(MODEL_PATH):
        for f in LEGACY_FILES:  # v1 artefacts are superseded by the bundle
            if os.path.exists(f):
                os.remove(f)
    print(f"\nSaved model bundle to {args.model_out}; reports in {os.path.abspath(reports)}")


if __name__ == "__main__":
    main()
