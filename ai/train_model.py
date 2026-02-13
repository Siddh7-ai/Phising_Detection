# === ai/train_model.py ===
"""
train_model.py (v2 — works with features.py v2, 18 features)
--------------------------------------------------------------
PHASE 2:
- Dataset cleaning & balancing
- Multi-model training and evaluation
- Automatic best-model selection (F1-score)
- False Positive Rate tracking (key metric)
- Confusion matrix output
- Overfitting prevention
- Save ONLY the best model

IMPORTANT:
  This file requires features.py v2 (18 features).
  If you update features.py you MUST retrain — the old
  phishing_model.pkl was built on 11 features and will crash.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

DATA_PATH = os.path.join(BASE_DIR, "data", "sample_urls.csv")
MODEL_OUTPUT_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")

from ai.features import extract_features, get_feature_count


# ============================================================================
# DATASET LOADING & CLEANING
# ============================================================================

def load_and_clean_dataset(csv_path: str):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'url' and 'label' columns")

    print("\n=== DATASET STATS (BEFORE CLEANING) ===")
    print(df["label"].value_counts())

    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str)
    df = df.drop_duplicates(subset=["url"])

    features = []
    labels = []
    skipped = 0

    for _, row in df.iterrows():
        try:
            feats = extract_features(row["url"])
            # Guard: only accept rows that match current feature count
            if len(feats) != get_feature_count():
                skipped += 1
                continue
            features.append(feats)
            labels.append(int(row["label"]))
        except Exception as e:
            print(f"  Warning: skipped {row['url'][:60]} — {e}")
            skipped += 1
            continue

    if skipped:
        print(f"  Skipped {skipped} rows due to errors.")

    X = np.array(features)
    y = np.array(labels)

    print("\n=== DATASET STATS (AFTER CLEANING) ===")
    unique, counts = np.unique(y, return_counts=True)
    for cls, cnt in zip(unique, counts):
        label_name = "Legitimate" if cls == 0 else "Phishing"
        print(f"  Class {cls} ({label_name}): {cnt}")

    return X, y


# ============================================================================
# DATASET BALANCING
# ============================================================================

def balance_dataset(X, y, random_state=42):
    """Undersample the majority class to create a balanced dataset."""
    classes, counts = np.unique(y, return_counts=True)
    min_count = counts.min()

    print(f"\n=== BALANCING DATASET ===")
    print(f"  Original distribution: {dict(zip(classes.tolist(), counts.tolist()))}")
    print(f"  Balancing to {min_count} samples per class")

    rng = np.random.default_rng(random_state)
    indices = []

    for cls in classes:
        cls_idx = np.where(y == cls)[0]
        selected = rng.choice(cls_idx, min_count, replace=False)
        indices.extend(selected.tolist())

    indices = np.array(indices)
    rng.shuffle(indices)

    X_balanced = X[indices]
    y_balanced = y[indices]

    new_dist = dict(zip(*[c.tolist() for c in np.unique(y_balanced, return_counts=True)]))
    print(f"  Balanced distribution: {new_dist}")

    return X_balanced, y_balanced


# ============================================================================
# MODEL TRAINING & EVALUATION
# ============================================================================

def train_and_evaluate_models(X_train, X_test, y_train, y_test):
    """Train three models and print full metrics including FPR."""

    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            solver="lbfgs",
            random_state=42,
            class_weight="balanced",
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            max_depth=15,          # Prevents overfitting
            min_samples_split=5,   # Prevents overfitting
            random_state=42,
            class_weight="balanced",
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,           # Prevents overfitting
            random_state=42,
        ),
    }

    results = {}

    for name, model in models.items():
        print(f"\n{'='*60}")
        print(f"  Training {name}...")
        print(f"{'='*60}")

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        accuracy  = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall    = recall_score(y_test, y_pred, zero_division=0)
        f1        = f1_score(y_test, y_pred, zero_division=0)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        results[name] = {
            "model":            model,
            "accuracy":         accuracy,
            "precision":        precision,
            "recall":           recall,
            "f1":               f1,
            "confusion_matrix": cm,
            "fpr":              fpr,
            "fnr":              fnr,
        }

        print(f"\n  === {name} Results ===")
        print(f"  Accuracy : {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall   : {recall:.4f}")
        print(f"  F1-Score : {f1:.4f}")
        print(f"\n  Confusion Matrix:")
        print(f"    TN: {tn:4d}   FP: {fp:4d}")
        print(f"    FN: {fn:4d}   TP: {tp:4d}")
        print(f"\n  False Positive Rate : {fpr:.4f}  {'✓ Under 5%' if fpr < 0.05 else '⚠ Above 5%'}")
        print(f"  False Negative Rate : {fnr:.4f}  {'✓ Under 5%' if fnr < 0.05 else '⚠ Above 5%'}")

    return results


# ============================================================================
# MODEL SELECTION
# ============================================================================

def select_best_model(results: dict):
    """Select the model with the best F1-score."""

    sorted_models = sorted(results.items(), key=lambda x: x[1]["f1"], reverse=True)

    print(f"\n{'='*60}")
    print("  MODEL COMPARISON (sorted by F1-score)")
    print(f"{'='*60}")
    print(f"  {'Model':<22} F1      Accuracy  FPR")
    print(f"  {'-'*50}")
    for name, metrics in sorted_models:
        print(
            f"  {name:<22} {metrics['f1']:.4f}  "
            f"{metrics['accuracy']:.4f}    {metrics['fpr']:.4f}"
        )

    best_name  = sorted_models[0][0]
    best_model = sorted_models[0][1]["model"]

    if not hasattr(best_model, "predict_proba"):
        raise RuntimeError("Selected model does not support predict_proba()")

    print(f"\n  ✓ Best Model Selected: {best_name}")
    print(f"    F1-Score : {sorted_models[0][1]['f1']:.4f}")
    print(f"    FPR      : {sorted_models[0][1]['fpr']:.4f}")

    return best_model


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    print("=" * 60)
    print("  PHISHING DETECTION MODEL TRAINING  (features v2, 18-dim)")
    print("=" * 60)

    print(f"\n[1/6] Loading and cleaning dataset...")
    X, y = load_and_clean_dataset(DATA_PATH)

    print(f"\n[2/6] Balancing dataset...")
    X, y = balance_dataset(X, y)

    print(f"\n[3/6] Splitting train/test data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Training samples : {len(X_train)}")
    print(f"  Testing  samples : {len(X_test)}")
    print(f"  Feature  dims    : {X_train.shape[1]}")

    print(f"\n[4/6] Training and evaluating models...")
    results = train_and_evaluate_models(X_train, X_test, y_train, y_test)

    print(f"\n[5/6] Selecting best model...")
    best_model = select_best_model(results)

    print(f"\n[6/6] Saving model...")
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
    joblib.dump(best_model, MODEL_OUTPUT_PATH)

    print(f"\n{'='*60}")
    print(f"  ✓ Model successfully saved to:")
    print(f"    {MODEL_OUTPUT_PATH}")
    print(f"{'='*60}")
    print("\n  ✓ Training complete!  Restart your backend server now.")
    print("  ✓ Reload the Chrome extension at chrome://extensions/")


if __name__ == "__main__":
    main()