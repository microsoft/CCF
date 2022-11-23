# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.


from loguru import logger as LOG  # type: ignore


def flush_info(lines, log_capture=None, depth=0):
    for line in lines:
        if log_capture is None:
            LOG.opt(colors=True, depth=depth + 1).info(line)
        else:
            log_capture.append(line)
