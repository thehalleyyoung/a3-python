"""Machine Learning Pipeline - main module."""
from data_loader import DataLoader, load_csv
from model import NeuralNetwork, train_model
from metrics import calculate_accuracy, calculate_f1


class MLPipeline:
    def __init__(self, config: dict):
        self.config = config
        self.models = []
        self.results = []
    
    def add_model(self, model):
        self.models.append(model)
    
    def get_model(self, index: int):
        """Get model by index."""
        # BUG: BOUNDS
        return self.models[index]
    
    def get_config_param(self, key: str):
        """Get config parameter."""
        # BUG: NULL_PTR
        value = self.config.get(key)
        return value.lower()
    
    def train_all(self, data):
        for model in self.models:
            train_model(model, data)
    
    def calculate_avg_accuracy(self) -> float:
        """Calculate average accuracy across models."""
        total = sum(r['accuracy'] for r in self.results)
        # BUG: DIV_ZERO
        return total / len(self.results)


def preprocess_data(data: list, feature_idx: int) -> list:
    """Extract feature from data."""
    result = []
    for row in data:
        # BUG: BOUNDS
        result.append(row[feature_idx])
    return result


def normalize_features(features: list, max_val: float) -> list:
    """Normalize features to 0-1 range."""
    # BUG: DIV_ZERO
    return [f / max_val for f in features]


def get_best_model(models: list, scores: list) -> object:
    """Get model with best score."""
    best_idx = scores.index(max(scores))
    # BUG: BOUNDS - models and scores could be misaligned
    return models[best_idx]


def safe_normalize(features: list, max_val: float) -> list:
    """Safe normalization."""
    if max_val == 0:
        return features
    return [f / max_val for f in features]
