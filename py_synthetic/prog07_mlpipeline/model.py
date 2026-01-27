"""Neural network model."""
from typing import List


class NeuralNetwork:
    def __init__(self, layers: List[int]):
        self.layers = layers
        self.weights = []
        self.biases = []
        self.gradients = []
    
    def get_layer_size(self, index: int) -> int:
        """Get layer size."""
        # BUG: BOUNDS
        return self.layers[index]
    
    def get_weight(self, layer: int) -> list:
        """Get weights for layer."""
        # BUG: BOUNDS
        return self.weights[layer]
    
    def forward(self, x: list) -> list:
        """Forward pass."""
        result = x
        for i, layer_size in enumerate(self.layers):
            # Simulated forward pass
            result = [0.0] * layer_size
        return result
    
    def get_gradient(self, layer: int) -> list:
        """Get gradient for layer."""
        # BUG: BOUNDS
        return self.gradients[layer]


def train_model(model: NeuralNetwork, data: list, epochs: int = 10):
    """Train the model."""
    for epoch in range(epochs):
        for batch in data:
            # Simulated training
            pass


def calculate_loss(predictions: list, targets: list) -> float:
    """Calculate mean squared error."""
    if not predictions:
        return 0.0
    total = sum((p - t) ** 2 for p, t in zip(predictions, targets))
    # BUG: DIV_ZERO if empty (but we check above)
    return total / len(predictions)


def get_prediction(model: NeuralNetwork, input_data: list, output_idx: int) -> float:
    """Get specific output from prediction."""
    output = model.forward(input_data)
    # BUG: BOUNDS
    return output[output_idx]


def calculate_learning_rate(base_lr: float, decay: float, epoch: int) -> float:
    """Calculate decayed learning rate."""
    # No bug - simple multiplication
    return base_lr * (decay ** epoch)


def normalize_gradients(gradients: list, max_norm: float) -> list:
    """Clip gradients to max norm."""
    norm = sum(g ** 2 for g in gradients) ** 0.5
    # BUG: DIV_ZERO if norm is 0
    if norm > max_norm:
        scale = max_norm / norm
        return [g * scale for g in gradients]
    return gradients


def get_layer_output(outputs: list, layer: int) -> list:
    """Get output of specific layer."""
    # BUG: BOUNDS
    return outputs[layer]
