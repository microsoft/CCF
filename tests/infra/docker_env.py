# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os


def is_docker_env():
    """Returns true if the process executing _this_ code already runs inside Docker"""
    return os.path.isfile("/.dockerenv")


def is_azure_devops_env():
    return "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI" in os.environ


def map_azure_devops_docker_workspace_dir(workspace_dir):
    return workspace_dir.replace("__w", "/mnt/vss/_work")


def map_workspace_if_azure_devops(workspace_dir):
    # When running in Azure DevOps CI inside a container, map
    # workspace directory before setting it as a volume in the container.
    # This is because containers spun up by the CI are sibling containers,
    # spun up by the docker daemon running on the host VM.
    if is_azure_devops_env():
        return map_azure_devops_docker_workspace_dir(workspace_dir)
    else:
        return workspace_dir
