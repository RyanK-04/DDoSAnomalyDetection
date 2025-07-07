import os
import time
import pandas as pd
import numpy as np
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from xgboost import XGBClassifier
from joblib import dump
import pyshark
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
PCAP_PATH = r"filepath"
CSV_PATH = r"filepath"
MODEL_PATH = "save the model"
SCALER_PATH = "save the scaler"
TEST_SIZE = 0.8
RANDOM_STATE = 42
MAX_PCAP_PACKETS = 5000


def extract_pcap_features(pcap_path, max_packets=5000):
    print(f"Extracting features from PCAP: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, display_filter="ip")
    flow_stats = defaultdict(lambda: {
        'packet_count': 0,
        'total_bytes': 0,
        'timestamps': [],
        'protocol': None
    })

    count = 0
    for pkt in cap:
        if 'IP' not in pkt:
            continue
        try:
            flow_key = (pkt.ip.src, pkt.ip.dst, pkt.highest_layer)
            stats = flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['total_bytes'] += int(pkt.length)
            stats['timestamps'].append(float(pkt.sniff_timestamp))
            stats['protocol'] = pkt.highest_layer
            count += 1
            if count >= max_packets:
                break
        except Exception:
            continue
    cap.close()

    features = []
    for flow_key, stats in flow_stats.items():
        if len(stats['timestamps']) < 2:
            continue
        diffs = np.diff(stats['timestamps'])
        flow_duration = stats['timestamps'][-1] - stats['timestamps'][0]
        features.append({
            'Flow Duration': flow_duration,
            'Total Fwd Packets': stats['packet_count'],
            'Total Backward Packets': 0,
            'Flow Bytes/s': stats['total_bytes'] / max(1e-5, flow_duration),
            'Flow Packets/s': stats['packet_count'] / max(1e-5, flow_duration),
            'Flow IAT Mean': np.mean(diffs),
            'Flow IAT Std': np.std(diffs),
            'Flow IAT Max': np.max(diffs),
            'Flow IAT Min': np.min(diffs),
            'Label': 1
        })

    return pd.DataFrame(features)


def load_csv_data(csv_path):
    print(f"Loading CSV: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df['Label'].isin(['BENIGN', 'DDoS'])]

    label_map = {'BENIGN': 0, 'DDoS': 1}
    df['Label'] = df['Label'].map(label_map)

    selected_columns = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Label'
    ]

    return df[selected_columns]


def train_model(X_train, y_train, X_val, y_val):
    print("Training XGBoost model...")
    model = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        scale_pos_weight=1
    )

    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=True)
    return model


def plot_confusion(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["BENIGN", "DDoS"], yticklabels=["BENIGN", "DDoS"])
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.show()


def plot_feature_importance(model, feature_names):
    importance = model.feature_importances_
    indices = np.argsort(importance)
    plt.figure(figsize=(10, 6))
    plt.barh(range(len(indices)), importance[indices], align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel("Feature Importance")
    plt.title("XGBoost Feature Importance")
    plt.tight_layout()
    plt.show()


def evaluate_model(model, X, y_true, feature_names=None):
    print("\nEvaluating Model...")
    y_pred = model.predict(X)

    print("\nMetrics:")
    print(f"- Accuracy:  {accuracy_score(y_true, y_pred):.4f}")
    print(f"- Precision: {precision_score(y_true, y_pred):.4f}")
    print(f"- Recall:    {recall_score(y_true, y_pred):.4f}")
    print(f"- F1 Score:  {f1_score(y_true, y_pred):.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_true, y_pred))
    plot_confusion(y_true, y_pred)

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "DDoS"]))

    if feature_names is not None:
        plot_feature_importance(model, feature_names)


def main():
    df_pcap = extract_pcap_features(PCAP_PATH, max_packets=MAX_PCAP_PACKETS)
    df_csv = load_csv_data(CSV_PATH)

    print(f"PCAP samples: {len(df_pcap)}, CSV samples: {len(df_csv)}")
    df = pd.concat([df_pcap, df_csv], ignore_index=True)

    # Visualize class balance
    plt.figure(figsize=(6, 4))
    df['Label'].value_counts().plot(kind='bar', color=['green', 'red'])
    plt.xticks(ticks=[0, 1], labels=["BENIGN", "DDoS"], rotation=0)
    plt.title("Class Distribution")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

    X = df.drop('Label', axis=1)
    y = df['Label']

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.dropna(inplace=True)
    y = y.loc[X.index]

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    dump(scaler, SCALER_PATH)

    model = train_model(X_train_scaled, y_train, X_val_scaled, y_val)
    dump(model, MODEL_PATH)
    print(f"Model saved to: {MODEL_PATH}")

    evaluate_model(model, X_val_scaled, y_val, feature_names=X.columns)


if __name__ == "__main__":
    start = time.time()
    main()
    print(f"\nTotal execution time: {time.time() - start:.2f} seconds")
