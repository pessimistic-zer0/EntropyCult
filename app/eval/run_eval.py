import os
import sys
import pandas as pd
import time
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Ensure app modules are importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app.engine.orchestrator import analyze_message

def run_evaluation(dataset_path: str):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return

    if 'text' not in df.columns or 'label' not in df.columns:
        print("Dataset must have 'text' and 'label' columns.")
        return

    print(f"Running evaluation on {len(df)} samples...")
    
    y_true = df['label'].astype(int).tolist()
    y_pred = []
    latencies = []

    # Run inference
    for index, row in df.iterrows():
        text = str(row['text'])
        
        # Measure Latency
        start_time = time.time()
        # Use a dummy ID for evaluation
        response = analyze_message(f"eval_{index}", text)
        end_time = time.time()
        
        latencies.append((end_time - start_time) * 1000) # ms

        # Determine prediction based on classification
        # In dataset: 1 = Malicious, 0 = Benign
        # In system: 'malicious' or 'benign'
        cls = response.get('classification', 'benign')
        y_pred.append(1 if cls == 'malicious' else 0)

    # Calculate Metrics
    print("\n" + "="*40)
    print("MANDATORY DELIVERABLE: EVALUATION METRICS")
    print("="*40)
    
    # Latency
    avg_latency = sum(latencies) / len(latencies)
    p95_latency = sorted(latencies)[int(0.95 * len(latencies))]
    print(f"\n⚡ Performance Metrics:")
    print(f"   - Average Latency: {avg_latency:.2f} ms")
    print(f"   - 95th Percentile: {p95_latency:.2f} ms")

    # Accuracy / FPs / FNs
    print(f"\n🎯 Accuracy Metrics:")
    acc = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"   - Accuracy: {acc:.2%}")
    print(f"   - False Positives (Benign marked Malicious): {fp}")
    print(f"   - False Negatives (Malicious marked Benign): {fn}")
    print(f"   - True Positives: {tp}")
    print(f"   - True Negatives: {tn}")
    
    print("\n📋 Detailed Classification Report:")
    print(classification_report(y_true, y_pred, target_names=['Benign', 'Malicious']))

if __name__ == "__main__":
    # Default to test set if available, else train
    dataset = "Slab_dataset/test.csv"
    if not os.path.exists(dataset):
        dataset = "Slab_dataset/train.csv"
        print("Test set not found, using train set for demo evaluation.")
    
    run_evaluation(dataset)
