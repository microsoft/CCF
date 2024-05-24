# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import json

BENCHER_FILE = "bencher.json"


class Bencher:
    def __init__(self):
        if not os.path.isfile(BENCHER_FILE):
            with open(BENCHER_FILE, "w+") as bf:
                json.dump({}, bf)

    def set(self, key, value):
        with open(BENCHER_FILE, "r") as bf:
            data = json.load(bf)
        data[key] = value
        with open(BENCHER_FILE, "w") as bf:
            json.dump(data, bf, indent=4)
