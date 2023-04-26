# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os

IS_SNP = os.path.exists("/dev/sev")

# It is the responsibility of the infra spinning up ACI container
# to populate this file with relevant environment variables
WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH = "/aci_env"

# Confidential ACI public preview (can be removed once all ACI regions/clusters
# have been updated before GA)
ACI_SEV_SNP_ENVVAR_SECURITY_POLICY = "UVM_SECURITY_POLICY"
ACI_SEV_SNP_ENVVAR_UVM_ENDORSEMENTS = "UVM_REFERENCE_INFO"
ACI_SEV_SNP_ENVVAR_REPORT_ENDORSEMENTS = "UVM_HOST_AMD_CERTIFICATE"

# Confidential ACI GA
ACI_SEV_SNP_ENVVAR_UVM_SECURITY_CONTEXT_DIR = "UVM_SECURITY_CONTEXT_DIR"
ACI_SEV_SNP_FILENAME_SECURITY_POLICY = "security-policy-base64"
ACI_SEV_SNP_FILENAME_UVM_ENDORSEMENTS = "reference-info-base64"
ACI_SEV_SNP_FILENAME_REPORT_ENDORSEMENTS = "host-amd-cert-base64"

# Specifying the full security policy is not mandatory for security guarantees
# (it's only useful for auditing/debugging) and so this may not be recorded in
# the ledger
EMPTY_SNP_SECURITY_POLICY = ""


def get_aci_env():
    env = {}
    with open(WELL_KNOWN_ACI_ENVIRONMENT_FILE_PATH, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            env_key, env_value = line.partition("=")[::2]
            env[env_key] = env_value
    return env


def _read_aci_environment_variable(envvar_name):
    env = get_aci_env()
    return env[envvar_name]


def get_security_context_dir():
    assert IS_SNP
    try:
        return _read_aci_environment_variable(
            ACI_SEV_SNP_ENVVAR_UVM_SECURITY_CONTEXT_DIR
        )
    except KeyError:
        return None
