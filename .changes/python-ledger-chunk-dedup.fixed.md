`ccf.ledger.Ledger` now reads a ledger chunk that is committed in only some of the given directories regardless of the order of those directories, preferring its committed copy, then a completed copy over an open one.
With `contiguous_suffix=True`, conflicting chunk ranges are only rejected if they are part of the selected suffix.
