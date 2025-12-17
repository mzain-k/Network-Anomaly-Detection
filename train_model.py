# ---------------------------------------------------------
# 1. IMPORT REQUIRED LIBRARIES
# ---------------------------------------------------------
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib


# ---------------------------------------------------------
# STEP 1: LOAD DATASET
# ---------------------------------------------------------
print("Loading dataset...")

data = pd.read_csv(r'C:\Users\Admin\OneDrive\Desktop\Python\Network Anomaly Detector\final_project_dataset.csv')

print("Total samples:", len(data))


# ---------------------------------------------------------
# STEP 2: FEATURE SELECTION & CLEANING
# ---------------------------------------------------------
# Drop non-numeric (text) columns + optional attack_type column
drop_columns = ["label", "frame.time", "ip.src", "ip.dst"]

# If attack_type exists (from advanced generator), drop it safely
if "attack_type" in data.columns:
    drop_columns.append("attack_type")

X = data.drop(columns=drop_columns)   # Input features
y = data["label"]                     # Target (0 = Normal, 1 = Attack)

print("Features used for training:", list(X.columns))
print("\nClass Distribution:")
print(y.value_counts())


# ---------------------------------------------------------
# STEP 3: TRAIN-TEST SPLIT (STRATIFIED)
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y   # ✅ keeps attack/normal ratio same in train & test
)


# ---------------------------------------------------------
# STEP 4: MODEL CREATION & TRAINING
# ---------------------------------------------------------
print("\nTraining the model... Please wait...")

model = RandomForestClassifier(
    n_estimators=200,        # More trees = better stability
    random_state=42,
    class_weight="balanced" # ✅ Handles attack imbalance automatically
)

model.fit(X_train, y_train)

print("✅ Training completed!")


# ---------------------------------------------------------
# STEP 5: MODEL TESTING & EVALUATION
# ---------------------------------------------------------
print("\nTesting the model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n✅ Accuracy Score:", accuracy)
print("\n✅ Classification Report:\n")
print(classification_report(y_test, predictions))


# ---------------------------------------------------------
# STEP 6: SAVE THE TRAINED MODEL
# ---------------------------------------------------------
print("\nSaving the model as 'traffic_guard.pkl'...")

joblib.dump(model, "traffic_guard.pkl")

print("✅ Model saved successfully!")
print("✅ Your TCPDump AI Intrusion Detection Model is READY!")
