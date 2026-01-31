# app/eval/train_model.py
import os
import sys
import pandas as pd
import argparse

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.engine.classifier import SklearnClassifier

def train(dataset_path: str, model_save_path: str):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return

    if 'text' not in df.columns or 'label' not in df.columns:
        print("Dataset must have 'text' and 'label' columns.")
        return

    texts = df['text'].astype(str).tolist()
    labels = df['label'].astype(int).tolist()

    print(f"Training on {len(texts)} samples...")
    classifier = SklearnClassifier(model_path=model_save_path)
    classifier.train(texts, labels)

    # Ensure valid directory for model
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    classifier.save()
    print("Training complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the prompt injection classifier")
    parser.add_argument("--dataset", type=str, default="Slab_dataset/train.csv", help="Path to training CSV")
    parser.add_argument("--output", type=str, default="data/models/classifier.joblib", help="Path to save model")
    
    args = parser.parse_args()
    
    # Resolve absolute paths
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    dataset_path = os.path.join(root_dir, args.dataset)
    output_path = os.path.join(root_dir, args.output)

    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        sys.exit(1)

    train(dataset_path, output_path)
