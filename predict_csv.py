import pandas as pd
import joblib

# Load trained model
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
