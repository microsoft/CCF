# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from collections.abc import Sequence

EWMA_HALF_LIFE = 7
EWMA_ALPHA = 1 - 0.5 ** (1 / EWMA_HALF_LIFE)


def ewma(values: Sequence[float], alpha: float = EWMA_ALPHA) -> float:
    """Return the exponentially weighted moving average of the values."""
    if not values:
        raise ValueError("Cannot calculate an EWMA without values")

    average = values[0]
    for value in values[1:]:
        average = alpha * value + (1 - alpha) * average
    return average
