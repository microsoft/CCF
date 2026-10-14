# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

ARG BASE_IMAGE=mcr.microsoft.com/azurelinux-beta/base/core:4.0
FROM ${BASE_IMAGE}

RUN dnf -y update

RUN dnf -y install gcc gcc-c++ make binutils gawk tar gzip ca-certificates git curl openssh-server \
    && sed -i '1iPermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes' /etc/ssh/sshd_config

COPY sshd/start_sshd.sh /usr/local/share/start_sshd.sh
ENTRYPOINT ["/usr/local/share/start_sshd.sh"]
CMD ["/bin/sh", "-c", "echo Container started\ntrap \"exit 0\" 15\nexec \"$@\"\nwhile sleep 1 & wait $!; do :; done", "-"]
