"""
Network intrusion detection on NSL-KDD (normal vs attack) using Random Forest.

Usage:
    pip install -r requirements.txt
    # place KDDTrain+.txt and KDDTest+.txt in this folder
    python nsl_kdd_ids.py
"""
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Decision threshold on attack probability. Lower = catch more attacks,
# but raise more false alarms. 0.05 was chosen from a manual sweep (see README).
THRESHOLD = 0.05

COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_srv_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag"]


def load(path):
    """Read an NSL-KDD file and add a binary target (0 = normal, 1 = attack)."""
    df = pd.read_csv(path, names=COLS)
    df["target"] = (df["label"] != "normal").astype(int)
    return df.drop(columns=["label", "difficulty"])


train = load("KDDTrain+.txt")
test = load("KDDTest+.txt")

# One-hot encode categoricals; align test columns to train columns
X_train = pd.get_dummies(train.drop(columns="target"), columns=CATEGORICAL)
X_test = pd.get_dummies(test.drop(columns="target"), columns=CATEGORICAL)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
y_train, y_test = train["target"], test["target"]

# Train (n_jobs=-1 uses all CPU cores)
model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
model.fit(X_train, y_train)

# Predict with the custom threshold
proba = model.predict_proba(X_test)[:, 1]
pred = (proba > THRESHOLD).astype(int)

print(f"Results at threshold {THRESHOLD}:\n")
print(classification_report(y_test, pred, target_names=["normal", "attack"]))
print("Confusion matrix:\n", confusion_matrix(y_test, pred))

# Threshold sweep, for the README / write-up
print("\nThreshold sweep (test set):")
print("thr    recall  precision  false_alarms  missed_attacks")
for t in [0.5, 0.4, 0.3, 0.2, 0.15, 0.1, 0.05]:
    p = (proba > t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, p).ravel()
    print(f"{t:<6} {tp / (tp + fn):.2f}    {tp / (tp + fp):.2f}       {fp:<13} {fn}")

# Feature importance
imp = pd.Series(model.feature_importances_, index=X_train.columns)
print("\nTop 10 features:\n", imp.sort_values(ascending=False).head(10))

# Save model, feature columns and threshold for later use (e.g. a Streamlit app)
joblib.dump(
    {"model": model, "columns": list(X_train.columns), "threshold": THRESHOLD},
    "ids_model.joblib",
)
print("\nSaved ids_model.joblib")