"""Metrics calculation utilities."""
from typing import List


def calculate_accuracy(predictions: List[int], labels: List[int]) -> float:
    """Calculate classification accuracy."""
    if not predictions:
        return 0.0
    correct = sum(1 for p, l in zip(predictions, labels) if p == l)
    return correct / len(predictions)


def calculate_precision(tp: int, fp: int) -> float:
    """Calculate precision."""
    # BUG: DIV_ZERO
    return tp / (tp + fp)


def calculate_recall(tp: int, fn: int) -> float:
    """Calculate recall."""
    # BUG: DIV_ZERO
    return tp / (tp + fn)


def calculate_f1(precision: float, recall: float) -> float:
    """Calculate F1 score."""
    # BUG: DIV_ZERO
    return 2 * (precision * recall) / (precision + recall)


def get_confusion_matrix_value(matrix: List[List[int]], row: int, col: int) -> int:
    """Get value from confusion matrix."""
    # BUG: BOUNDS
    return matrix[row][col]


def calculate_mse(predictions: list, targets: list) -> float:
    """Calculate mean squared error."""
    total = sum((p - t) ** 2 for p, t in zip(predictions, targets))
    # BUG: DIV_ZERO
    return total / len(predictions)


def calculate_rmse(mse: float) -> float:
    """Calculate root mean squared error."""
    return mse ** 0.5


def get_metric_at_epoch(metrics: list, epoch: int) -> float:
    """Get metric value at specific epoch."""
    # BUG: BOUNDS
    return metrics[epoch]


def calculate_auc(fpr: list, tpr: list) -> float:
    """Calculate area under ROC curve (simplified)."""
    area = 0.0
    for i in range(1, len(fpr)):
        # BUG: BOUNDS on first iteration if fpr/tpr empty
        width = fpr[i] - fpr[i-1]
        height = (tpr[i] + tpr[i-1]) / 2
        area += width * height
    return area


def safe_calculate_f1(precision: float, recall: float) -> float:
    """Safe F1 calculation."""
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)


def safe_calculate_precision(tp: int, fp: int) -> float:
    """Safe precision calculation."""
    total = tp + fp
    if total == 0:
        return 0.0
    return tp / total
