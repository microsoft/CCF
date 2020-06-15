Accepting Recovery and Submitting Shares
========================================

.. note:: Before members can initiate the end of the recovery procedure, operators should have started a new network and recovered all public transactions. See :ref:`details for public recovery operator procedure <operators/recovery:Establishing a Recovered Public Network>`.

.. note:: See :ref:`users/deploy_app:Recovering a Service` for an automated way to recover a defunct CCF service.

Accepting Recovery
------------------

Once the public recovered network has been established by operators, members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery procedure.

A member proposes to recover the network and other members can vote on the proposal:

.. code-block:: bash

    $ cat accept_recovery.json
    {
        "script": {
            "text": "tables = ...; return Calls:call(\"accept_recovery\")"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/propose --cacert network_cert --key member1_privk --cert member1_cert --data-binary @accept_recovery.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 1
    }

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    false

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept_1.json -H "content-type: application/json"
    true

Once the proposal to recover the network has passed under the rules of the :term:`Constitution`, the recovered service is ready for members to submit their recovery shares.

Submitting Recovery Shares
--------------------------

To restore private transactions and complete the recovery procedure, members shoud submit their recovery shares. The number of members required to submit their shares is set by the ``recovery_threshold`` CCF configuration parameter and :ref:`can be updated by the consortium at any time <members/common_member_operations:Updating Recovery Threshold>`.

.. note:: The members who submit their recovery shares do not necessarily have to be the members who previously accepted the recovery.

First, members should retrieve their encrypted recovery shares via the ``recovery_share`` RPC [#recovery_share]_.

.. code-block:: bash

    $ curl https://<ccf-node-address>/members/recovery_share -X GET --cacert network_cert --key member1_privk --cert member1_cert -H "content-type: application/json"

Then, members should decrypt their shares using their private encryption key and the `previous` network public encryption key (output by the first node of the now-defunct service via the ``network-enc-pubk-file`` :ref:`command line option <operators/start_network:Starting the First Node>`) using `NaCl's public-key authenticated encryption <https://nacl.cr.yp.to/box.html>`_.

Finally, members should submit their decrypted share to CCF via the ``recovery_share/submit`` RPC:

.. code-block:: bash

    $ cat submit_recovery_share.json
    {"recovery_share": [<recovery_share_bytes>]}

    $ curl https://<ccf-node-address>/members/recovery_share/submit -X POST --data-binary @submit_recovery_share.json --cacert network_cert --key member1_privk --cert member1_cert -H "content-type: application/json"
    false

    $ curl https://<ccf-node-address>/members/recovery_share/submit -X POST --data-binary @submit_recovery_share.json --cacert network_cert --key member2_privk --cert member2_cert -H "content-type: application/json"
    true

When the recovery threshold is reached, the ``recovery_share/submit`` RPC returns ``true``. At this point, the private recovery procedure is started and the private ledger is being recovered.

.. note:: While all nodes are recovering the private ledger, no new transaction can be executed by the network.

Once the recovery of the private ledger is complete on a quorum of nodes that have joined the new network, the ledger is fully recovered and users are able to continue issuing business transactions.

.. note:: Recovery shares are updated every time a new member is added or retired and when the ledger is rekeyed. It also possible for members to update the recovery shares via the ``update_recovery_shares`` proposal.

Summary Diagram
---------------

.. mermaid::

    sequenceDiagram
        participant Member 0
        participant Member 1
        participant Users
        participant Node 2
        participant Node 3

        Note over Node 2, Node 3: Operators have restarted a public-only service

        Member 0->>+Node 2: Propose accept_recovery
        Node 2-->>Member 0: Proposal ID
        Member 1->>+Node 2: Vote for Proposal ID
        Node 2-->>Member 1: State: ACCEPTED
        Note over Node 2, Node 3: accept_recovery proposal completes. Service is ready to accept recovery shares.

        Member 0->>+Node 2: recovery_share
        Node 2-->>Member 0: Encrypted recovery share for Member 0
        Note over Member 0: Decrypts recovery share
        Member 0->>+Node 2: recovery_share/submit: {"recovery_share": ...}
        Node 2-->>Member 0: False

        Member 1->>+Node 2: recovery_share
        Node 2-->>Member 1: Encrypted recovery share for Member 1
        Note over Member 1: Decrypts recovery share
        Member 1->>+Node 2: recovery_share/submit: {"recovery_share": ...}
        Node 2-->>Member 1: True

        Note over Node 2, Node 3: Reading Private Ledger...

        Note over Node 2: Recovery procedure complete
        Note over Node 3: Recovery procedure complete


.. rubric:: Footnotes

.. [#recovery_share] Recovery shares are encrypted with the respective member public key and stored in CCF. As such, a recovery share can only be retrieved and used by the member who owns it.