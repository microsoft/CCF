# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

ARG BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core:3.0
FROM ${BASE_IMAGE}

# Trust Microsoft-signed packages
RUN gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY  \
    && tdnf -y update

# Basic dev deps, helps smoothly install VSCode server and enables Codespaces SSH.
RUN tdnf -y install build-essential openssh-server \
    && sed -i '1iPermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes' /etc/ssh/sshd_config

COPY start_sshd.sh /usr/local/share/start_sshd.sh
ENTRYPOINT ["/usr/local/share/start_sshd.sh"]
CMD ["/bin/sh", "-c", "echo Container started\ntrap \"exit 0\" 15\nexec \"$@\"\nwhile sleep 1 & wait $!; do :; done", "-"]
