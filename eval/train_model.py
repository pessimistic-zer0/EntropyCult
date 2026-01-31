from __future__ import annotations

import argparse
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.pipeline import FeatureUnion, Pipeline


def load_csv(path: str) -> tuple[list[str], list[int]]:
    df = pd.read_csv(path)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{path} must have columns: text,label (found {df.columns.tolist()})")
    X = df["text"].astype(str).tolist()
    y = df["label"].astype(int).tolist()
    return X, y


def build_model() -> Pipeline:
    feats = FeatureUnion(
        transformer_list=[
            ("word", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=50_000)),
            ("char", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), max_features=75_000)),
        ],
        n_jobs=-1,
    )

    clf = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        n_jobs=-1,
    )

    return Pipeline([("tfidf", feats), ("clf", clf)])

def evaluate(model: Pipeline, name: str, X: list[str], y: list[int]) -> None:
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)
    print(f"\n=== {name} ===")
    try:
        print("ROC-AUC:", roc_auc_score(y, probs))
    except Exception as e:
        print("ROC-AUC: (failed)", e)
    print(classification_report(y, preds, digits=4))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/train.csv")
    ap.add_argument("--val", default="data/validation.csv")
    ap.add_argument("--test", default="data/test.csv")
    ap.add_argument("--out", default="models/pi_model.joblib")
    args = ap.parse_args()

    X_train, y_train = load_csv(args.train)
    X_val, y_val = load_csv(args.val)
    X_test, y_test = load_csv(args.test)

    model = build_model()
    model.fit(X_train, y_train)

    evaluate(model, "validation", X_val, y_val)
    evaluate(model, "test", X_test, y_test)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump(model, args.out)
    print(f"\nSaved model to: {args.out}")


if __name__ == "__main__":
    main()