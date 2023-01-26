# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from hashlib import sha256
import base64

IS_SNP = os.path.exists("/dev/sev")

# It is the responsibility of the infra spinning up ACI container
# to populate this file with relevant environment variables
WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH = "/aci_env"

ACI_SEV_SNP_ENVVAR_SECURITY_POLICY = "UVM_SECURITY_POLICY"
ACI_SEV_SNP_ENVVAR_UVM_ENDORSEMENTS = "UVM_REFERENCE_INFO"

# Specifying the full security policy is not mandatory for security guarantees
# (it's only useful for auditing/debugging) and so this may not be recorded in
# the ledger
EMPTY_SNP_SECURITY_POLICY = ""


def _read_aci_environment_variable(envvar_name):
    with open(WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH, "r", encoding="utf-8") as lines:
        for line in lines:
            env_key, env_value = line.partition("=")[::2]
            if env_key == envvar_name:
                return env_value
    raise ValueError(
        f"Environment variable {envvar_name} does not exist in {WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH}"
    )


def get_aci_env():
    env = {}
    with open(WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH, "r", encoding="utf-8") as lines:
        for line in lines:
            env_key, env_value = line.partition("=")[::2]
            env[env_key] = env_value
    return env


def get_container_group_security_policy_base64():
    assert IS_SNP
    return _read_aci_environment_variable(ACI_SEV_SNP_ENVVAR_SECURITY_POLICY)


def get_container_group_security_policy():
    return base64.b64decode(get_container_group_security_policy_base64()).decode()


def get_container_group_security_policy_digest():
    return sha256(get_container_group_security_policy())


def get_container_group_uvm_endorsements_base64():
    assert IS_SNP
    return _read_aci_environment_variable(ACI_SEV_SNP_ENVVAR_UVM_ENDORSEMENTS)


def get_container_group_uvm_endorsements():
    return base64.b64decode(get_container_group_uvm_endorsements_base64()).decode()
