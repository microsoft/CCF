# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from contextlib import contextmanager


@contextmanager
def modify_env(**kwargs):
    existing_env = dict()
    for k, v in kwargs.items():
        existing_env[k] = os.environ.get(k)
        os.environ[k] = v
    yield
    for k, v in existing_env.items():
        if v is None:
            del os.environ[k]
        else:
            os.environ[k] = v
