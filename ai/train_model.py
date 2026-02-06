# === ai/train_model.py ===
"""
train_model.py
---------------
Train and evaluate the Machine Learning model for
the Phishing Website Detection System.

Model:
- Random Forest Classifier (scikit-learn)

Why Random Forest?
- Handles non-linear feature interactions well
- Robust to noise
- Provides feature importance (explainability)
- Strong recall performance (security-first mindset)

Output:
- Trained model saved as model/phishing_model.pkl
- Evaluation metrics printed to console
"""

import os
import sys
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

# ------------------------------------------------------------------
# PATH SETUP (ROBUST & OS-INDEPENDENT)
# ------------------------------------------------------------------

# Absolute path to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add project root to PYTHONPATH so imports work everywhere
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Paths
DATA_PATH = os.path.join(BASE_DIR, "data", "sample_urls.csv")
MODEL_OUTPUT_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")

# Import after path fix
from ai.features import extract_features


# ------------------------------------------------------------------
# DATA LOADING
# ------------------------------------------------------------------
def load_dataset(csv_path: str):
    """
    Load dataset and extract features.

    CSV must contain:
    - url
    - label (0 = legitimate, 1 = phishing)
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain 'url' and 'label' columns")

    X = df["url"].apply(extract_features).tolist()
    y = df["label"].values

    return X, y


# ------------------------------------------------------------------
# MODEL TRAINING
# ------------------------------------------------------------------
def train_model(X, y):
    """
    Train Random Forest classifier.
    Emphasis on high recall to minimize false negatives.
    """
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        class_weight={0: 1, 1: 2}  # Penalize phishing false negatives
    )

    model.fit(X, y)
    return model


# ------------------------------------------------------------------
# MODEL EVALUATION
# ------------------------------------------------------------------
def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance and print metrics.
    """
    y_pred = model.predict(X_test)

    print("\n=== MODEL EVALUATION ===")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))


# ------------------------------------------------------------------
# MAIN PIPELINE
# ------------------------------------------------------------------
def main():
    print("[+] Loading dataset...")
    X, y = load_dataset(DATA_PATH)

    print("[+] Splitting train/test data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("[+] Training Random Forest model...")
    model = train_model(X_train, y_train)

    print("[+] Evaluating model...")
    evaluate_model(model, X_test, y_test)

    # Ensure model directory exists
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)

    print("[+] Saving trained model...")
    joblib.dump(model, MODEL_OUTPUT_PATH)

    print(f"[✓] Model saved to: {MODEL_OUTPUT_PATH}")


# ------------------------------------------------------------------
if __name__ == "__main__":
    main()
