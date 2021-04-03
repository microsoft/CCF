#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
set -ex

# This only checks that the following commands do not throw errors.
# It is expected that other tests cover correctness of the generated
# proposals, this just checks the basic usability of the CLI.

keygenerator.sh --help
keygenerator.sh --name alice
keygenerator.sh --name bob --gen-enc-key

export JS_GOVERNANCE=1

python -m ccf.proposal_generator --help

python -m ccf.proposal_generator set_member --help
python -m ccf.proposal_generator set_member bob_cert.pem bob_enc_pubk.pem
python -m ccf.proposal_generator set_member bob_cert.pem bob_enc_pubk.pem '"Arbitrary data"'
python -m ccf.proposal_generator set_member bob_cert.pem bob_enc_pubk.pem '{"Interesting": {"nested": ["da", "ta"]}}'

python -m ccf.proposal_generator set_user --help
python -m ccf.proposal_generator set_user alice_cert.pem
python -m ccf.proposal_generator set_user alice_cert.pem '"ADMIN"'
python -m ccf.proposal_generator set_user alice_cert.pem '{"type": "ADMIN", "friendlyName": "Alice"}'

python -m ccf.proposal_generator transition_service_to_open --help
python -m ccf.proposal_generator transition_service_to_open

python -m ccf.proposal_generator trust_node --help
python -m ccf.proposal_generator trust_node 42

python -m ccf.proposal_generator new_node_code --help
python -m ccf.proposal_generator new_node_code 1234abcd
