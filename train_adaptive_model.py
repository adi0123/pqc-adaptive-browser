"""
Adaptive ML-KEM Algorithm Selector — Model Training
====================================================
Trains a Random Forest classifier to select between:
    ML-KEM-512   (fast, lower security overhead)
    ML-KEM-768   (balanced — default)
    ML-KEM-1024  (maximum security)

Features used for prediction:
    bandwidth_bytes      — estimated available bandwidth
    network_latency_ms   — measured TCP RTT
    packet_size_bytes    — ClientHello packet size
    handshake_history_ms — average recent handshake time
    security_level       — host classification (1=low, 3=high)
    x25519_ms            — X25519 keygen time
    mlkem_ms             — ML-KEM keygen time
    hybrid_ms            — hybrid combination time

Labels:
    0 → ML-KEM-512
    1 → ML-KEM-768
    2 → ML-KEM-1024
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import os
import csv

# ============================================================
# CONSTANTS
# ============================================================

MODEL_FILE    = "adaptive_model.pkl"
CSV_FILE      = "proxy_logs/tls_sessions.csv"
RANDOM_STATE  = 42

FEATURE_NAMES = [
    "bandwidth_bytes",
    "network_latency_ms",
    "packet_size_bytes",
    "handshake_history_ms",
    "security_level",
    "x25519_ms",
    "mlkem_ms",
    "hybrid_ms",
]

LABEL_NAMES = {
    0: "ML-KEM-512",
    1: "ML-KEM-768",
    2: "ML-KEM-1024"
}

# ============================================================
# LABELING LOGIC
# Determines the OPTIMAL algorithm for each set of conditions
# ============================================================

def label_sample(
    bandwidth,
    latency_ms,
    packet_size,
    handshake_history_ms,
    security_level,
    x25519_ms,
    mlkem_ms,
    hybrid_ms
):
    """
    Assign the optimal ML-KEM algorithm label for a sample.

    Decision logic (represents the expert knowledge that
    the ML model learns to approximate):

    security_level == 3 (bank, gov, mil):
        → Always ML-KEM-1024 (maximum quantum resistance)

    security_level == 2 (mail, cloud, api, auth):
        → ML-KEM-768 if network is good
        → ML-KEM-512 if network is severely constrained

    security_level == 1 (default, low-risk):
        → ML-KEM-512 if latency is high or bandwidth is low
        → ML-KEM-768 as default
    """

    # --------------------------------------------------------
    # High security domain → always maximum protection
    # --------------------------------------------------------
    if security_level == 3:
        return 2  # ML-KEM-1024

    # --------------------------------------------------------
    # Network constraint indicators
    # --------------------------------------------------------
    very_low_bandwidth   = bandwidth < 3000       # < 3 KB
    low_bandwidth        = bandwidth < 20000      # < 20 KB
    high_latency         = latency_ms > 300       # > 300 ms
    very_high_latency    = latency_ms > 600       # > 600 ms
    slow_handshake_hist  = handshake_history_ms > 1500

    # --------------------------------------------------------
    # Medium security domain
    # --------------------------------------------------------
    if security_level == 2:

        if very_low_bandwidth or very_high_latency:
            return 0  # ML-KEM-512 — constrained network

        if low_bandwidth or high_latency or slow_handshake_hist:
            return 1  # ML-KEM-768 — balanced

        return 1  # ML-KEM-768 — default for medium security

    # --------------------------------------------------------
    # Low / default security
    # --------------------------------------------------------
    if security_level <= 1:

        if very_high_latency or very_low_bandwidth:
            return 0  # ML-KEM-512 — prioritise speed

        if high_latency or low_bandwidth:
            return 0  # ML-KEM-512 — still prefer lighter

        return 1  # ML-KEM-768 — standard default

    return 1  # Safe fallback


# ============================================================
# SYNTHETIC DATASET GENERATION
# ============================================================

def generate_synthetic_data(n_samples=5000):
    """
    Generate a diverse synthetic training dataset.
    Covers a wide range of network conditions and
    security levels.
    """
    print(f"Generating {n_samples} synthetic samples...")

    np.random.seed(RANDOM_STATE)

    rows = []

    # Scenario distribution (reflects real-world traffic mix)
    scenarios = [
        # (weight, bandwidth_range, latency_range)
        (0.30, (50000, 500000), (5,  50)),    # Fast home/office
        (0.25, (10000, 80000),  (20, 100)),   # Moderate network
        (0.20, (2000,  20000),  (50, 250)),   # Slow network
        (0.15, (500,   5000),   (100, 500)),  # Very slow / mobile
        (0.10, (100,   2000),   (200, 1000)), # Severely constrained
    ]

    security_distribution = [1, 1, 1, 2, 2, 3]  # Weighted realistic

    for _ in range(n_samples):

        # Pick a scenario
        weights = [s[0] for s in scenarios]
        weights = np.array(weights) / sum(weights)
        idx = np.random.choice(len(scenarios), p=weights)
        _, bw_range, lat_range = scenarios[idx]

        bandwidth  = np.random.uniform(*bw_range)
        latency_ms = np.random.uniform(*lat_range)

        packet_size = np.random.uniform(800, 2000)

        # Historical handshake time correlates with latency
        handshake_history_ms = (
            latency_ms * np.random.uniform(1.5, 4.0)
            + np.random.normal(0, 50)
        )
        handshake_history_ms = max(0, handshake_history_ms)

        security_level = int(
            np.random.choice(security_distribution)
        )

        # Crypto timings (from your CSV observations)
        x25519_ms = np.random.uniform(0.08, 0.40)
        mlkem_ms  = np.random.uniform(0.06, 0.80)
        hybrid_ms = np.random.uniform(0.001, 0.05)

        label = label_sample(
            bandwidth,
            latency_ms,
            packet_size,
            handshake_history_ms,
            security_level,
            x25519_ms,
            mlkem_ms,
            hybrid_ms,
        )

        rows.append([
            bandwidth,
            latency_ms,
            packet_size,
            handshake_history_ms,
            security_level,
            x25519_ms,
            mlkem_ms,
            hybrid_ms,
            label,
        ])

    df = pd.DataFrame(
        rows,
        columns=FEATURE_NAMES + ["label"]
    )

    # Show distribution
    print("\nSynthetic label distribution:")
    for lbl, name in LABEL_NAMES.items():
        count = (df["label"] == lbl).sum()
        pct   = 100 * count / len(df)
        print(f"  {name}: {count} samples ({pct:.1f}%)")

    return df


# ============================================================
# LOAD REAL CSV DATA (if available)
# ============================================================

def load_real_data():
    """
    Load real handshake timing data from proxy CSV logs.
    Uses timing columns as features and infers network
    conditions from handshake time.

    Note: network bandwidth/latency aren't logged yet,
    so they are estimated from handshake timing.
    """

    if not os.path.exists(CSV_FILE):
        print(f"No real CSV found at {CSV_FILE}")
        return None

    try:
        df = pd.read_csv(CSV_FILE)
        print(f"\nLoaded {len(df)} real samples from {CSV_FILE}")
    except Exception as e:
        print(f"Could not load CSV: {e}")
        return None

    rows = []

    for _, row in df.iterrows():

        try:

            handshake_ms = float(row.get("Handshake_ms", 1.0))
            x25519_ms    = float(row.get("X25519_ms", 0.15))
            mlkem_ms     = float(row.get("MLKEM_ms", 0.15))
            hybrid_ms    = float(row.get("Hybrid_ms", 0.002))

            # Estimate network features from handshake time
            # (heuristic — replace with real measurements later)
            estimated_latency   = handshake_ms * 0.3
            estimated_bandwidth = max(
                1000,
                100000 / max(handshake_ms, 0.1)
            )
            packet_size         = 1216  # ML-KEM-768 hybrid
            history_ms          = handshake_ms

            # All real data is ML-KEM-768 (label = 1)
            # since that's what your proxy used
            security_level = 1
            label = 1  # ML-KEM-768

            rows.append([
                estimated_bandwidth,
                estimated_latency,
                packet_size,
                history_ms,
                security_level,
                x25519_ms,
                mlkem_ms,
                hybrid_ms,
                label,
            ])

        except Exception:
            continue

    if not rows:
        return None

    df_real = pd.DataFrame(
        rows,
        columns=FEATURE_NAMES + ["label"]
    )

    print(f"Real data samples converted: {len(df_real)}")
    return df_real


# ============================================================
# TRAIN MODEL
# ============================================================

def train():

    print("=" * 55)
    print("  ADAPTIVE ML-KEM MODEL TRAINING")
    print("=" * 55)

    # --------------------------------------------------------
    # Build dataset
    # --------------------------------------------------------

    df_synth = generate_synthetic_data(n_samples=5000)

    df_real = load_real_data()

    if df_real is not None and len(df_real) > 0:

        df_all = pd.concat(
            [df_synth, df_real],
            ignore_index=True
        )
        print(
            f"\nCombined dataset: "
            f"{len(df_synth)} synthetic + "
            f"{len(df_real)} real = "
            f"{len(df_all)} total samples"
        )

    else:

        df_all = df_synth
        print(
            f"\nUsing synthetic data only: "
            f"{len(df_all)} samples"
        )

    X = df_all[FEATURE_NAMES].values
    y = df_all["label"].values

    # --------------------------------------------------------
    # Train / Test Split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set:     {len(X_test)} samples")

    # --------------------------------------------------------
    # Train Random Forest
    # --------------------------------------------------------

    print("\nTraining Random Forest classifier...")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    y_pred = model.predict(X_test)

    print("\n" + "=" * 55)
    print("  MODEL EVALUATION")
    print("=" * 55)

    # Overall accuracy
    accuracy = (y_pred == y_test).mean()
    print(f"  Test Accuracy: {accuracy * 100:.2f}%")

    # Cross-validation
    cv_scores = cross_val_score(
        model, X, y, cv=5, scoring="accuracy"
    )
    print(
        f"  5-Fold CV:     "
        f"{cv_scores.mean() * 100:.2f}% "
        f"(± {cv_scores.std() * 100:.2f}%)"
    )

    # Per-class report
    print("\n  Per-class results:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=list(LABEL_NAMES.values()),
        digits=3
    ))

    # Feature importance
    print("  Feature importances:")
    importances = model.feature_importances_
    sorted_idx  = np.argsort(importances)[::-1]
    for i in sorted_idx:
        print(
            f"    {FEATURE_NAMES[i]:<25} "
            f"{importances[i] * 100:.2f}%"
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    joblib.dump(model, MODEL_FILE)

    print(f"\n  Model saved → {MODEL_FILE}")
    print("=" * 55)

    # --------------------------------------------------------
    # Quick smoke test — same as proxy.py's predict() call
    # --------------------------------------------------------

    print("\n  Smoke test (simulated predict calls):")

    test_cases = [
        {
            "desc": "High security bank site, good network",
            "features": [100000, 20, 1216, 200, 3, 0.15, 0.15, 0.002],
        },
        {
            "desc": "Low security, fast network",
            "features": [200000, 10, 1216, 100, 1, 0.12, 0.12, 0.001],
        },
        {
            "desc": "Medium security, slow mobile network",
            "features": [2000, 400, 1216, 800, 2, 0.20, 0.20, 0.003],
        },
        {
            "desc": "Medium security, constrained IoT",
            "features": [500, 600, 800, 1500, 2, 0.30, 0.30, 0.005],
        },
        {
            "desc": "Government site, any network",
            "features": [10000, 80, 1216, 500, 3, 0.15, 0.15, 0.002],
        },
    ]

    for case in test_cases:
        prediction = model.predict([case["features"]])[0]
        algo = LABEL_NAMES[int(prediction)]
        print(f"    [{algo}]  {case['desc']}")

    print("\nDone. Run your proxy — adaptive model is ready.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    # Install dependencies if needed
    try:
        import sklearn
        import joblib
    except ImportError:
        print("Installing required packages...")
        os.system(
            "pip install scikit-learn joblib pandas "
            "numpy --break-system-packages"
        )

    train()
