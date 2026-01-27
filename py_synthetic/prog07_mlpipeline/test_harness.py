"""Test harness for ML pipeline - triggers buggy functions."""


def test_get_model_oob():
    """Get model at bad index - triggers BOUNDS."""
    models = []
    index = 0
    # BUG: BOUNDS
    return models[index]


def test_get_config_param_none():
    """Get config param when missing - triggers NULL_PTR."""
    config = {}
    key = "learning_rate"
    value = config.get(key)
    # BUG: NULL_PTR
    return value.lower()


def test_calculate_avg_accuracy_empty():
    """Calculate avg with empty results - triggers DIV_ZERO."""
    results = []
    total = sum(r.get('accuracy', 0) for r in results)
    # BUG: DIV_ZERO
    return total / len(results)


def test_preprocess_data_oob():
    """Preprocess with bad feature index - triggers BOUNDS."""
    data = [[1, 2], [3, 4]]
    feature_idx = 10
    result = []
    for row in data:
        # BUG: BOUNDS
        result.append(row[feature_idx])


def test_normalize_features_zero():
    """Normalize with zero max - triggers DIV_ZERO."""
    features = [1.0, 2.0, 3.0]
    max_val = 0.0
    # BUG: DIV_ZERO
    return [f / max_val for f in features]


def test_get_row_oob():
    """Get row at bad index - triggers BOUNDS."""
    data = []
    index = 0
    # BUG: BOUNDS
    return data[index]


def test_get_header_oob():
    """Get header at bad index - triggers BOUNDS."""
    headers = []
    index = 0
    # BUG: BOUNDS
    return headers[index]


def test_get_batch_oob():
    """Get batch beyond data length - triggers BOUNDS."""
    data = [1, 2, 3]
    batch_idx = 0
    batch_size = 10
    start = batch_idx * batch_size
    end = start + batch_size
    # BUG: BOUNDS
    return [data[i] for i in range(start, end)]


def test_calculate_batch_count_zero():
    """Calculate batches with zero size - triggers DIV_ZERO."""
    data_size = 100
    batch_size = 0
    # BUG: DIV_ZERO
    return data_size // batch_size


def test_get_sample_oob():
    """Get samples at bad indices - triggers BOUNDS."""
    data = [1, 2, 3]
    indices = [0, 5, 10]
    result = []
    for idx in indices:
        # BUG: BOUNDS
        result.append(data[idx])


def test_get_layer_size_oob():
    """Get layer size at bad index - triggers BOUNDS."""
    layers = [10, 20, 10]
    index = 10
    # BUG: BOUNDS
    return layers[index]


def test_get_weight_oob():
    """Get weight at bad layer - triggers BOUNDS."""
    weights = []
    layer = 0
    # BUG: BOUNDS
    return weights[layer]


def test_get_gradient_oob():
    """Get gradient at bad layer - triggers BOUNDS."""
    gradients = []
    layer = 0
    # BUG: BOUNDS
    return gradients[layer]


def test_get_prediction_oob():
    """Get prediction at bad output index - triggers BOUNDS."""
    output = [0.1, 0.9]
    output_idx = 10
    # BUG: BOUNDS
    return output[output_idx]


def test_normalize_gradients_zero():
    """Normalize with zero norm - triggers DIV_ZERO."""
    gradients = [0.0, 0.0, 0.0]
    max_norm = 1.0
    norm = sum(g ** 2 for g in gradients) ** 0.5  # 0.0
    if norm > max_norm:
        # BUG: DIV_ZERO (but won't happen here due to condition)
        scale = max_norm / norm
    # Force the division
    # BUG: DIV_ZERO
    return max_norm / norm


def test_get_layer_output_oob():
    """Get layer output at bad layer - triggers BOUNDS."""
    outputs = []
    layer = 0
    # BUG: BOUNDS
    return outputs[layer]


def test_calculate_precision_zero():
    """Calculate precision with zero denominator - triggers DIV_ZERO."""
    tp = 0
    fp = 0
    # BUG: DIV_ZERO
    return tp / (tp + fp)


def test_calculate_recall_zero():
    """Calculate recall with zero denominator - triggers DIV_ZERO."""
    tp = 0
    fn = 0
    # BUG: DIV_ZERO
    return tp / (tp + fn)


def test_calculate_f1_zero():
    """Calculate F1 with zero sum - triggers DIV_ZERO."""
    precision = 0.0
    recall = 0.0
    # BUG: DIV_ZERO
    return 2 * (precision * recall) / (precision + recall)


def test_get_confusion_matrix_oob():
    """Get matrix value at bad index - triggers BOUNDS."""
    matrix = [[1, 0], [0, 1]]
    row = 5
    col = 5
    # BUG: BOUNDS
    return matrix[row][col]


def test_calculate_mse_empty():
    """Calculate MSE with empty data - triggers DIV_ZERO."""
    predictions = []
    targets = []
    total = sum((p - t) ** 2 for p, t in zip(predictions, targets))
    # BUG: DIV_ZERO
    return total / len(predictions)


def test_get_metric_at_epoch_oob():
    """Get metric at bad epoch - triggers BOUNDS."""
    metrics = [0.1, 0.2, 0.3]
    epoch = 10
    # BUG: BOUNDS
    return metrics[epoch]


# Run tests
if __name__ == "__main__":
    try:
        test_calculate_precision_zero()
    except ZeroDivisionError:
        pass
