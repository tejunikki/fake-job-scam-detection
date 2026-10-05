"""
model.py
--------
Trains a TF-IDF + Logistic Regression classifier that labels a job-offer
message as one of: legitimate, suspicious, scam.

If dataset.csv is missing or too small to train/evaluate reliably, a small
demo dataset is generated programmatically so the app can still run end to
end. Run this file directly to (re)train and save model.pkl:

    python model.py
"""

import os
import csv
import random
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

LABELS = ["legitimate", "suspicious", "scam"]
MIN_ROWS_PER_CLASS = 4  # minimum rows per class needed for a meaningful train/test split


def _build_fallback_dataset():
    """Create a small, balanced demo dataset in memory when dataset.csv is
    missing or too small. This keeps the app runnable out of the box."""
    legit = [
        "We are pleased to offer you the position at our company. Please find the official offer letter attached.",
        "Thank you for interviewing with us. The panel would like to invite you for a second round interview.",
        "Your application has been shortlisted. Please confirm your availability for a technical interview.",
        "Congratulations, please find attached the formal offer letter with salary details and joining date.",
        "HR will share the employee handbook and onboarding schedule on your first day at the office.",
        "Please log in to our official careers portal to complete your background verification.",
        "Your reference checks are complete, the signed offer will be sent from our official company domain.",
    ]
    suspicious = [
        "You are selected, please pay a refundable registration fee to confirm your seat.",
        "Work from home and earn a large monthly income doing simple data entry, join our Telegram group.",
        "Congratulations, you are shortlisted, please share your bank details so we can process your joining kit.",
        "Pay for the training kit and laptop deposit, it will be refunded after your first salary.",
        "You are selected, no interview needed, just complete registration by paying a small fee.",
        "Earn money weekly working part time from home, contact us on WhatsApp only.",
    ]
    scam = [
        "URGENT you WON the job, send your bank account number, OTP and PIN immediately to claim your bonus.",
        "Congratulations, pay now via a suspicious payment link to secure your job, offer expires in one hour.",
        "You are selected, share your OTP and password right now or you will lose the offer.",
        "Click this link and enter your card number and CVV to receive your salary advance today only.",
        "Final notice, transfer the registration amount within 30 minutes or your seat will be cancelled.",
        "Act now, share your debit card details to receive an advance salary, limited time urgent offer.",
    ]
    rows = [(t, "legitimate") for t in legit] + [(t, "suspicious") for t in suspicious] + [(t, "scam") for t in scam]
    random.shuffle(rows)
    return pd.DataFrame(rows, columns=["text", "label"])


def load_dataset():
    """Load dataset.csv if it exists and has enough rows per class,
    otherwise fall back to a small programmatic demo dataset."""
    df = None
    used_fallback = False

    if os.path.exists(DATASET_PATH):
        try:
            df = pd.read_csv(DATASET_PATH)
            df = df.dropna(subset=["text", "label"])
            df["label"] = df["label"].str.strip().str.lower()
            df = df[df["label"].isin(LABELS)]
        except Exception:
            df = None

    if df is None or df.empty:
        df = _build_fallback_dataset()
        used_fallback = True
    else:
        counts = df["label"].value_counts()
        if any(counts.get(lbl, 0) < MIN_ROWS_PER_CLASS for lbl in LABELS):
            # Not enough data for a reliable split -> top up with fallback rows
            df = pd.concat([df, _build_fallback_dataset()], ignore_index=True)
            used_fallback = True

    return df.reset_index(drop=True), used_fallback


def train_model():
    """Train the TF-IDF + Logistic Regression pipeline and persist it,
    along with evaluation metrics, to model.pkl."""
    df, used_fallback = load_dataset()

    X = df["text"].astype(str).tolist()
    y = df["label"].tolist()

    metrics = None
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        max_features=5000,
    )

    # Only attempt a held-out evaluation split if there is enough data;
    # otherwise train on everything and skip metrics rather than fabricate them.
    can_split = len(df) >= 15 and df["label"].value_counts().min() >= 3
    if can_split:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)

        clf = LogisticRegression(max_iter=1000, class_weight="balanced")
        clf.fit(X_train_vec, y_train)

        y_pred = clf.predict(X_test_vec)
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 3),
            "precision": round(float(precision_score(y_test, y_pred, average="macro", zero_division=0)), 3),
            "recall": round(float(recall_score(y_test, y_pred, average="macro", zero_division=0)), 3),
            "f1_score": round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 3),
            "test_size": len(y_test),
            "train_size": len(y_train),
        }

        # Refit on the full dataset for the final deployed model
        X_full_vec = vectorizer.fit_transform(X)
        clf.fit(X_full_vec, y)
    else:
        X_full_vec = vectorizer.fit_transform(X)
        clf = LogisticRegression(max_iter=1000, class_weight="balanced")
        clf.fit(X_full_vec, y)

    bundle = {
        "vectorizer": vectorizer,
        "classifier": clf,
        "labels": sorted(list(set(y))),
        "metrics": metrics,
        "used_fallback_data": used_fallback,
        "dataset_size": len(df),
    }
    joblib.dump(bundle, MODEL_PATH)
    return bundle


def load_or_train_model():
    """Load model.pkl if present; otherwise train it fresh. Any loading
    error triggers a clean retrain rather than crashing the app."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return train_model()


if __name__ == "__main__":
    bundle = train_model()
    print(f"Model trained on {bundle['dataset_size']} rows "
          f"(used fallback demo data: {bundle['used_fallback_data']})")
    if bundle["metrics"]:
        print("Evaluation metrics:", bundle["metrics"])
    else:
        print("Dataset too small for a held-out evaluation split; metrics not computed.")