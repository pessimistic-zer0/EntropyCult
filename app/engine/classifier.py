# app/engine/classifier.py
import joblib
import pandas as pd
from typing import List, Union
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, ClassifierMixin

class SklearnClassifier(BaseEstimator, ClassifierMixin):
    def __init__(self, model_path: str = "data/models/classifier.joblib"):
        self.model_path = model_path
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 3), analyzer='word', max_features=10000)),
            ('clf', LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced'))
        ])
        self.is_fitted = False

    def train(self, texts: List[str], labels: List[int]):
        """Train the model on texts and labels."""
        self.pipeline.fit(texts, labels)
        self.is_fitted = True

    def predict(self, texts: Union[str, List[str]]) -> List[float]:
        """Predict probability of maliciousness (class 1)."""
        if isinstance(texts, str):
            texts = [texts]
        
        if not self.is_fitted:
            # Try to load if not fitted in memory
            self.load()
            
        if not self.is_fitted:
            raise ValueError("Model not fitted and no saved model found.")

        # Return probability of class 1 (malicious)
        return self.pipeline.predict_proba(texts)[:, 1].tolist()

    def save(self):
        """Save the trained model to disk."""
        joblib.dump(self.pipeline, self.model_path)
        print(f"Model saved to {self.model_path}")

    def load(self):
        """Load the model from disk."""
        try:
            self.pipeline = joblib.load(self.model_path)
            self.is_fitted = True
            print(f"Model loaded from {self.model_path}")
        except FileNotFoundError:
            print(f"No model found at {self.model_path}")
            self.is_fitted = False
