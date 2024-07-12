Accepting Recovery and Submitting Shares
========================================

.. note:: Before members can initiate the end of the recovery procedure, operators should have started a new network and recovered all public transactions. See :ref:`details for public recovery operator procedure <operations/recovery:Establishing a Recovered Public Network>`.

Accepting Recovery
------------------

.. note:: The `ccf_cose_sign1` script is distributed in the `ccf` Python package, available on PyPI. It can be installed with `pip install ccf`.

Once the public recovered network has been established by operators, members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery procedure.

A member proposes to recover the network and other members can vote on the proposal:

.. code-block:: bash

    $ cat transition_service_to_open.json
    {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": {
                    "previous_service_identity": "-----BEGIN CERTIFICATE-----\nMIIBuDCCAT6gAwIBAgIRANWm4xJICc6i4sir+jRXE2gwCgYIKoZIzj0EAwMwFjEU\nMBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwMzExMTcwNTEyWhcNMjIwMzEyMTcw\nNTExWjAWMRQwEgYDVQQDDAtDQ0YgTmV0d29yazB2MBAGByqGSM49AgEGBSuBBAAi\nA2IABOyCL4ZOG0mu7fLpciVWcDHFp1dOVr1osONVgG/fhjjZryR/HS5xIc20d96L\nN4yl6qbtoEGE1r1juQB44xoEKOox7OLRD2S0N1/T/DfdCIdgyv5rAVIFCMZVtxGA\nsg6I26NQME4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUAz9Pfzi3sEN2w6KuncV2\n0wFXDC0wHwYDVR0jBBgwFoAUAz9Pfzi3sEN2w6KuncV20wFXDC0wCgYIKoZIzj0E\nAwMDaAAwZQIxAKM+T5Lvv4/2nKn8ZL87DkKiBwaGh1kLmrM/0xLhlQYgRp13iqw8\ndt/Zm+/dLCZe/AIwBrgsP5YM2TZ/AAHgC50H8+DKd0k/DfVIy28qhMb/6jr1bCMp\nf0CN7wvG22F59hDa\n-----END CERTIFICATE-----\n",
                    "next_service_identity": "-----BEGIN CERTIFICATE-----\nMIIBezCCASGgAwIBAgIRAOVHYf9qhvjzdoIw3fPHp5YwCgYIKoZIzj0EAwIwFjEU\nMBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwMzExMTcwNTQzWhcNMjIwMzEyMTcw\nNTQyWjAWMRQwEgYDVQQDDAtDQ0YgTmV0d29yazBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABBZXMHCrjfBeO+FHqDG8Szjzc4lQC8KmvTX8Il0ZERXH/mjLZ7Dc52rX\nnilD1ghdRDWXiKMQWT9RPvm4tefWHD6jUDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0O\nBBYEFCUmm9u05D0/IFupggFW5VgVlUSyMB8GA1UdIwQYMBaAFCUmm9u05D0/IFup\nggFW5VgVlUSyMAoGCCqGSM49BAMCA0gAMEUCIQCy6WoeLtTUD8GRIOM+oRNe/lTj\nRrrry+0AxZgxBU1oSwIgJmyrTfT90re+rzAkF9uiqoL44TVWkQf1t3cZrgVFYK8=\n-----END CERTIFICATE-----\n"
                }
            }
        ]
    }

.. code-block:: bash

    $ ccf_cose_sign1 \
      --ccf-gov-msg-type proposal \
      --ccf-gov-msg-created_at `date -uIs` \
      --signing-key member1_privk.pem \
      --signing-cert member1_cert.pem \
      --content transition_service_to_open.json \
    | curl https://<ccf-node-address>/gov/members/proposals:create?api-version=2024-07-01 \
      --cacert service_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose"
    {
        "ballotCount": 0,
        "proposalId": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposerId": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "proposalState": "Open"
    }

    $ ccf_cose_sign1 \
      --ccf-gov-msg-type ballot \
      --ccf-gov-msg-created_at `date -uIs` \
      --ccf-gov-msg-proposal_id 1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377 \
      --signing-key member1_privk.pem \
      --signing-cert member1_cert.pem \
      --content vote_accept.json \
    | curl https://<ccf-node-address>/gov/members/proposals/1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377/ballots/d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1:submit?api-version=2024-07-01 \
      --cacert service_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose"
    {
        "ballotCount": 1,
        "proposalId": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposerId": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "proposalState": "Open"
    }

    $ ccf_cose_sign1 \
      --ccf-gov-msg-type ballot \
      --ccf-gov-msg-created_at `date -uIs` \
      --ccf-gov-msg-proposal_id 1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377 \
      --signing-key member2_privk.pem \
      --signing-cert member2_cert.pem \
      --content vote_accept.json
    | curl https://<ccf-node-address>/gov/members/proposals/1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377/ballots/e306e3a6eead2f4a3854302b41c3015bf12db9535ac0be1b8cf6584f84bca92b:submit?api-version=2024-07-01 \
      --cacert service_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose"
    {
        "ballotCount": 2,
        "proposalId": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposerId": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "proposalState": "Accepted"
    }

Once the proposal to recover the network has passed under the rules of the :term:`Constitution`, the recovered service is ready for members to submit their recovery shares.

Note that the ``transition_service_to_open`` proposal takes two parameters: the previous and the next :term:`Service Identity` (x509 certificates in PEM format). This is to ensure that the correct network is recovered and to facilitate auditing, as well as to avoid forks. The previous :term:`Service Identity` is used to validate the snapshot the recovery node is started from; CCF will refuse to start from a snapshot where the signing node certificate is not endorsed by the previous :term:`Service Identity`. Since both identities are recorded on the ledger with the proposal, it is always clear at which point the identity changed.

.. note:: The ``previous_service_identity`` argument to the ``transition_service_to_open`` proposal is required for recovery, but must not be provided when opening a new service as there is no previous identity.

Submitting Recovery Shares
--------------------------

To restore private transactions and complete the recovery procedure, recovery members (i.e. members whose public encryption key has been registered in CCF) should submit their recovery shares. The number of members required to submit their shares is set by the ``recovery_threshold`` CCF configuration parameter and :ref:`can be updated by the consortium at any time <governance/common_member_operations:Updating Recovery Threshold>`.

.. note:: The recovery members who submit their recovery shares do not necessarily have to be the members who previously accepted the recovery.

Member recovery shares are stored in the ledger, encrypted with each member's public encryption key. Members can retrieve their encrypted recovery shares from the public-only service via the :http:GET:`/gov/recovery/encrypted-shares/{memberId}` endpoint, perform the share decryption securely (see for example :doc:`hsm_keys`) and submit the decrypted recovery share via the :http:POST:`/gov/recovery/members/{memberId}:recover` endpoint.

The recovery share retrieval, decryption and submission steps can be conveniently performed in one step using the ``submit_recovery_share.sh`` script:

.. code-block:: bash

    $ submit_recovery_share.sh https://<ccf-node-address> \
      --member-enc-privk member0_enc_privk.pem \
      --cert member0_cert.pem \ 
      --api-version 2024-07-01 \
      --key member0_privk.pem \
      --cacert service_cert.pem
    HTTP/1.1 200 OK
    content-type: text/plain
    x-ms-ccf-transaction-id: 4.28
    1/2 recovery shares successfully submitted.

    $ submit_recovery_share.sh https://<ccf-node-address> \
      --member-enc-privk member1_enc_privk.pem \
      --cert member1_cert.pem \
      --api-version 2024-07-01 \
      --key member1_privk.pem \
      --cacert service_cert.pem
    HTTP/1.1 200 OK
    content-type: text/plain
    x-ms-ccf-transaction-id: 4.30
    2/2 recovery shares successfully submitted. End of recovery procedure initiated.

When the recovery threshold is reached, the :http:POST:`/gov/recovery/members/{memberId}:recover` response signals that the end of the recovery procedure is initiated and that the private ledger is now being recovered. Operators and members can monitor the progress of the private recovery process via the :http:GET:`/node/state` endpoint.

.. note:: While all nodes are recovering the private ledger, no new transaction can be executed by the network.

Once the recovery of the private ledger is complete on a quorum of nodes that have joined the new network, the ledger is fully recovered and users are able to continue issuing business transactions.

.. note:: Recovery shares are updated every time a new recovery member is added or removed and when the ledger is rekeyed. It also possible for members to update the recovery shares via the ``trigger_recovery_shares_refresh`` proposal.

Summary Diagram
---------------

.. mermaid::

    sequenceDiagram
        participant Member A
        participant Member B
        participant Network

        Note over Network: Operators have restarted a public-only service

        Member A->>+Network: Propose transition_service_to_open
        Network-->>Member A: Proposal ID
        Member B->>+Network: Vote for Proposal ID
        Network-->>Member B: State: Accepted

        Note over Network: transition_service_to_open proposal completes. <br> Service is ready to accept recovery shares.

        Member A->>+Network: GET /gov/recovery/encrypted-shares/<member0_id>
        Network-->>Member A: Encrypted recovery share for Member A
        Note over Member A: Decrypts recovery share
        Member A->>+Network: POST /gov/recovery/members/<member0_id>:recover": "<recovery_share_0>"
        Network-->>Member A: 1/2 recovery shares successfully submitted.

        Member B->>+Network: GET /gov/recovery/encrypted-shares/<member1_id>
        Network-->>Member B: Encrypted recovery share for Member B
        Note over Member B: Decrypts recovery share
        Member B->>+Network: POST /gov/recovery/members/<member1_id>:recover": "<recovery_share_1>"
        Network-->>Member B: End of recovery procedure initiated.

        Note over Network: Reading Private Ledger...
        Note over Network: Recovery procedure complete
