# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import experiments

test_directory = experiments.create_test_directory()
local_servers = [f"127.0.0.1:800{i}" for i in range(5)]
experiments.all_tests(local_servers, test_directory)
