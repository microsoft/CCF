# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.partitions
import sys

from loguru import logger as LOG

if __name__ == "__main__":
    LOG.remove()
    LOG.add(
        sys.stdout,
        format="[{time:HH:mm:ss.SSS}] {message}",
    )

    if len(sys.argv) > 1 and sys.argv[1] in ["-d", "--dump"]:
        infra.partitions.Partitioner.dump()
    else:
        infra.partitions.Partitioner.dump()
        infra.partitions.Partitioner.cleanup()
