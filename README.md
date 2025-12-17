# Network Traffic Anomaly Detection Using Machine Learning

**Course:** Computer Networks (CS EE-374)  
**Department:** Computer Science  
**Date:** 18th December 2025  

## Submitted By

| Name               | CMS    |
|--------------------|--------|
| Muhammad Zain Khan | 512770 |
| Abdullah Khan      | 514779 |
| Ayesha Kakar       | 529027 |
| Hateem Arhum       | 526814 |
|                    |        |

---

## Abstract

With the exponential rise in cyberattacks, specifically network attacks, traditional firewall rules are often insufficient. This project implements a **Network Anomaly Detection System** that leverages **Machine Learning** to identify malicious traffic patterns. The system captures live network traffic using `tcpdump`, processes packet metadata using `tshark`, and utilizes a **Random Forest Classifier** to distinguish between normal web browsing behavior and **SYN Flood attacks**.

The model was trained on a synthetically generated dataset ensuring high-quality, balanced feature sets, achieving an accuracy of **100% on test data** (dataset size: 20,000 packets).

---

## Table of Contents

1. [Introduction](#chapter-1-introduction)  
2. [Theoretical Background](#chapter-2-theoretical-background)  
3. [Methodology](#chapter-3-methodology)  
4. [Implementation Details](#chapter-4-implementation-details)  
5. [Results and Analysis](#chapter-5-results-and-analysis)  
6. [Conclusion](#chapter-6-conclusion)  
7. [References](#references)

---

## Chapter 1: Introduction

### 1.1 Problem Statement

Modern networks face constant threats from automated scripts and botnets. A common attack vector is the **SYN Flood**, where an attacker overwhelms a server by sending thousands of connection requests (SYN packets) without completing the TCP handshake. Manual monitoring is infeasible due to the speed and volume of traffic.

### 1.2 Project Objectives

The primary objective is to build an automated “Brain” that analyzes network metadata and flags anomalies:

1.  Capture raw network traffic packets in real time.
2.  Extract key mathematical features (Window Size, Sequence Numbers, Flags).
3.  Train a Machine Learning model to classify traffic as:
    * **Normal (0)**
    * **Attack (1)**

### 1.3 Scope and Limitations

**Scope**
* Focuses on TCP traffic patterns.
* Detects SYN Flood attacks vs normal web browsing.

**Limitations**
* Analyzes packet headers only (no payload inspection).
* Assumes attack follows a flooding pattern.
* May not detect stealth or low-rate attacks.

---

## Chapter 2: Theoretical Background

### 2.1 TCP/IP Protocols & Flags

Transmission Control Protocol (TCP) uses flags to manage connections. This project focuses on:

* **SYN (Synchronize):** Initiates a connection.
* **ACK (Acknowledge):** Confirms data receipt.
* **Window Size:** Indicates how much data the receiver can process.

### 2.2 The SYN Flood Attack

In a normal TCP connection:
1.  Client sends SYN
2.  Server replies with SYN-ACK
3.  Client responds with ACK

In a **SYN Flood attack**, the attacker sends many SYN packets but never sends the final ACK. The server keeps ports half-open until resources are exhausted.

**Detection Pattern:**
* High volume of SYN packets
* Small, fixed packet sizes
* Abnormal window sizes

### 2.3 Random Forest Algorithm

The **Random Forest Classifier** creates multiple decision trees and aggregates their predictions. It was chosen because:
* It is robust against overfitting.
* Performs well for binary classification.
* Handles nonlinear feature relationships effectively.

---

## Chapter 3: Methodology

### 3.1 System Architecture

The system follows a linear pipeline:
1.  **Capture:** `tcpdump` listens on the network interface.
2.  **Bridge:** `tshark` converts PCAP files to CSV.
3.  **Preprocessing:** Python cleans and filters data.
4.  **Prediction:** Random Forest model classifies traffic.

### 3.2 Data Acquisition & Generation

Public datasets (e.g., KDD99) are outdated or incomplete. Therefore, a **synthetic dataset** was generated to mimic realistic traffic:

**Normal Traffic**
* HTTP/HTTPS behavior
* High variance in packet length
* Mostly ACK/PSH flags

**Attack Traffic**
* DoS-style traffic
* Fixed small packet sizes
* SYN flags only
* Rapid packet transmission

### 3.3 Feature Engineering

Features describe **behavior**, not identity. Source IPs were dropped to prevent memorization.

Selected features:
* `tcp.flags`: Packet intent
* `tcp.window_size`: Anomaly indicator
* `frame.len`: Packet size (bytes)
* `tcp.seq`: Sequence number

---

## Chapter 4: Implementation Details

### 4.1 Tools and Technologies

* **Operating System:** Linux (Ubuntu / Kali) via Virtual Machine
* **Packet Capture:** `tcpdump` (libpcap → PCAP)
* **Processing:** `tshark` (Wireshark CLI)
* **Language:** Python
* **Libraries:**
    * Pandas (data manipulation)
    * Scikit-learn (machine learning)

### 4.2 Tshark Bridge Command

```bash
tshark -r capture.pcap -T fields -E separator=, -E header=y \
-e frame.time -e tcp.flags -e tcp.window_size -e frame.len \
> training_data.csv
```

### 4.3 Training the Model (train_model.py)
This script loads the training dataset, preprocesses the features (removing IP/Time), trains the Random Forest classifier, and saves the trained model.

``` Code:
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
# Update path to your local dataset file
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
```

### 4.4 Predicting Anomalies (predict_csv.py)
This script loads the trained model (traffic_guard.pkl) and applies it to new, unseen network traffic (in CSV format) to detect attacks.

``` Code:
import pandas as pd
import joblib

# Load trained model
# Update path to where your .pkl file is saved
model = joblib.load(r'C:\Users\Admin\OneDrive\Desktop\Python\Network Anomaly Detector\traffic_guard.pkl')

# Load new unseen data (same format as training without label)
data = pd.read_csv(r'C:\Users\Admin\OneDrive\Desktop\Python\Network Anomaly Detector\test_dataset.csv')

# Predict attacks
predictions = model.predict(data)

data["Prediction"] = predictions

# Save results
data.to_csv("prediction_results.csv", index=False)

print("✅ Predictions completed!")
print("✅ Results saved as prediction_results.csv")
```

## Chapter 5: Results and Analysis

### 5.1 Evaluation Metrics

The model was evaluated using a 20% hold-out test set.

* **Accuracy:** Overall correctness.
* **Recall:** Ability to detect all attacks (critical for security).

### 5.2 Test Results

* **Accuracy:** 100%

**Confusion Matrix Results:**

* **17,000** Normal packets correctly classified
* **3,000** Attack packets correctly detected

---

## Chapter 6: Conclusion

This project demonstrates that Machine Learning can effectively automate network defense. By analyzing packet metadata rather than payload content, a lightweight and efficient system was developed to detect SYN Flood attacks with high accuracy.

Using `tshark` as a bridge between raw network captures and Python proved to be a robust design choice. Future improvements may include:

* Time-delta analysis between packets.
* Detection of low-rate and stealth attacks.
* Real-time deployment with alerting mechanisms.

---

## References

1.  **Scikit-learn Documentation:** [https://scikit-learn.org/](https://scikit-learn.org/)
2.  **Tcpdump Manual:** [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
3.  **Wireshark / Tshark Documentation:** [https://www.wireshark.org/docs/manpages/tshark.html](https://www.wireshark.org/docs/manpages/tshark.html)
4.  **Dataset Source:** Synthetic generation based on TCP/IP RFC standards.
