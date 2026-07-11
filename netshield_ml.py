import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt


# ---------------------------
# Load & preparing logs
# ---------------------------
def load_logs(filepath):
    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.fillna("Unknown", inplace=True)
    df["failed_flag"] = df["status"].apply(
        lambda x: 1 if "fail" in str(x).lower() else 0
    )
    df["hour"] = df["timestamp"].dt.hour
    return df


# ---------------------------
# Random Forest Training (simple supervised model)
# ---------------------------
def train_rf(df):
    df["label"] = df["failed_flag"].apply(lambda x: 1 if x == 1 else 0)

    X = df[["hour", "source_port", "dest_port"]]
    y = df["label"]

    model = RandomForestClassifier(n_estimators=80)
    model.fit(X, y)
    return model


# ---------------------------
# DBSCAN anomaly detection
# ---------------------------
def unsupervised_anomaly(df):
    features = df[["hour", "source_port", "dest_port", "failed_flag"]]
    scaled = StandardScaler().fit_transform(features)

    model = DBSCAN(eps=0.6, min_samples=4)
    labels = model.fit_predict(scaled)

    df["anomaly"] = labels
    anomalies = df[df["anomaly"] == -1]
    return anomalies


# ---------------------------
# Main NETSHIELD Pipeline
# ---------------------------
def run_netshield(filepath):
    df = load_logs(filepath)

    rf_model = train_rf(df)

    anomalies = unsupervised_anomaly(df)

    print("\n--- NETSHIELD REPORT ---")
    print("Total Events:", len(df))
    print("Anomalies Detected:", len(anomalies))

    return df, anomalies
