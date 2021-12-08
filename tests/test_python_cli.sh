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

build_proposal.sh --help
python -m ccf.ballot_builder --help

build_proposal.sh --action set_member cert @bob_cert.pem > set_member_proposal_a.json
python -m ccf.ballot_builder set_member_proposal_a.json > set_member_vote_for_a.json
build_proposal.sh --action set_member cert @bob_cert.pem encryption_pub_key @bob_enc_pubk.pem > set_member_proposal_b.json
python -m ccf.ballot_builder set_member_proposal_b.json > set_member_vote_for_b.json
build_proposal.sh --action set_member cert @bob_cert.pem encryption_pub_key @bob_enc_pubk.pem member_data 'Arbitrary data' > set_member_proposal_c.json
python -m ccf.ballot_builder set_member_proposal_c.json > set_member_vote_for_c.json
build_proposal.sh \
    --action set_member \
        cert @bob_cert.pem \
        encryption_pub_key @bob_enc_pubk.pem \
        -j member_data '{"Interesting": {"nested": ["da", "ta"]}}' \
    > set_member_proposal_d.json
python -m ccf.ballot_builder set_member_proposal_d.json > set_member_vote_for_d.json

build_proposal.sh --action set_user cert @alice_cert.pem > set_user_proposal_a.json
python -m ccf.ballot_builder set_user_proposal_a.json > set_user_vote_for_a.json
build_proposal.sh --action set_user cert @alice_cert.pem user_data 'ADMIN' > set_user_proposal_b.json
python -m ccf.ballot_builder set_user_proposal_b.json > set_user_vote_for_b.json
build_proposal.sh --action set_user cert @alice_cert.pem -j user_data '{"type": "ADMIN", "friendlyName ": "Alice"}' > set_user_proposal_c.json
python -m ccf.ballot_builder set_user_proposal_c.json > set_user_vote_for_c.json

build_proposal.sh --action transition_service_to_open > transition_service_to_open_proposal.json
python -m ccf.ballot_builder transition_service_to_open_proposal.json > transition_service_to_open_vote_for.json

build_proposal.sh --action transition_node_to_trusted node_id 42 valid_from 211019154318Z > transition_node_to_trusted_proposal.json
python -m ccf.ballot_builder transition_node_to_trusted_proposal.json > transition_node_to_trusted_vote_for.json

build_proposal.sh --action add_node_code code_id 1234abcd > add_node_code_proposal.json
python -m ccf.ballot_builder add_node_code_proposal.json > add_node_code_vote_for.json

CCF_ROOT_DIR="${1}"
python -m ccf.bundle_js_app --help
python -m ccf.bundle_js_app "${1}"/samples/apps/logging/js > bundle.json
build_proposal.sh --action set_js_app bundle -j @bundle.json > set_js_app_proposal.json
python -m ccf.ballot_builder set_js_app_proposal.json > set_js_app_vote_for.json
