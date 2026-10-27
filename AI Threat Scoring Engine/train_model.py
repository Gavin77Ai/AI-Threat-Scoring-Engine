
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "training_data.csv"
MODEL_FILE = BASE_DIR / "threat_model.pkl"

FEATURE_COLUMNS = [
    "unusual_country",
    "unknown_ip",
    "failed_attempts",
    "unusual_time",
    "success_after_failures"
]

BOOLEAN_COLUMNS = [
    "unusual_country",
    "unknown_ip",
    "unusual_time",
    "success_after_failures"
]


def main():
    data = pd.read_csv(DATA_FILE)

    required_columns = set(FEATURE_COLUMNS + ["label"])
    missing_columns = required_columns - set(data.columns)

    if missing_columns:
        raise ValueError(
            "Training data is missing columns: "
            + ", ".join(sorted(missing_columns))
        )

    X = data[FEATURE_COLUMNS].copy()
    y = data["label"].astype("string").str.strip()

    if X.isnull().any().any() or y.isnull().any():
        raise ValueError("Training data contains missing values.")

    if not set(y.unique()).issubset({"Benign", "Suspicious"}):
        raise ValueError("Labels must be Benign or Suspicious.")

    if y.nunique() < 2:
        raise ValueError("Training data must contain both labels.")

    for column in BOOLEAN_COLUMNS:
        values = X[column].astype(str).str.strip().str.lower()

        if not values.isin(["true", "false", "0", "1"]).all():
            raise ValueError(
                f"Column '{column}' must contain Boolean values."
            )

        X[column] = values.map({
            "true": 1,
            "false": 0,
            "1": 1,
            "0": 0
        }).astype(int)

    X["failed_attempts"] = pd.to_numeric(
        X["failed_attempts"],
        errors="coerce"
    )

    invalid_attempts = (
        X["failed_attempts"].isna()
        | (X["failed_attempts"] < 0)
        | (X["failed_attempts"] % 1 != 0)
    )

    if invalid_attempts.any():
        raise ValueError(
            "failed_attempts must contain non-negative integers."
        )

    X["failed_attempts"] = X["failed_attempts"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("\n=== Random Forest Threat Detection ===")
    print("Training examples:", len(X_train))
    print("Testing examples:", len(X_test))
    print("Accuracy:", round(accuracy_score(y_test, predictions), 3))

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["Benign", "Suspicious"],
            zero_division=0
        )
    )

    print("Confusion Matrix (rows = actual, columns = predicted)")
    print("Label order: Benign, Suspicious")
    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=["Benign", "Suspicious"]
        )
    )

    benign_data = X.loc[y == "Benign"].copy()

    if len(benign_data) < 5:
        raise ValueError(
            "At least 5 Benign examples are required to train "
            "the anomaly detector."
        )

    anomaly_detector = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    anomaly_detector.fit(benign_data)

    print("\n=== Isolation Forest Anomaly Detection ===")
    print("Benign baseline examples:", len(benign_data))
    print("Features used:", len(FEATURE_COLUMNS))
    print("Detector trained on Benign examples only.")

    joblib.dump(
        {
            "model": model,
            "anomaly_detector": anomaly_detector,
            "feature_columns": FEATURE_COLUMNS,
            "boolean_columns": BOOLEAN_COLUMNS
        },
        MODEL_FILE
    )

    print("\nModels saved to:", MODEL_FILE)
    print("Training complete.")


if __name__ == "__main__":
    main()

