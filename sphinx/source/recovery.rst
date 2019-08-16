Catastrophic Recovery
=====================

For unexpected reasons, all nodes in the network may crash while executing business transactions. In this catastrophic scenario, it is possible that the length of ledgers of each node may differ slightly since some transactions may not have yet been fully replicated.

.. note:: The current version of the recovery protocol relies on Intel SGX Sealing capability [#sealing]_.

However, one of the previous ledgers can be recovered and the execution of new business transactions continue if the following three conditions are met:

- At least one of the old nodes' CPU survived.
- The sealed network secret file (``sealed_secrets.<date>.<pid>``) associated with that CPU is available to the members.
- One of the ledgers (preferably the ledger of the previous primary as it is likely to be the longest) is available.

The recovery protocol consists of two phases. First, the public transactions of the previous network are restored and the new network established. Then, after the members have agreed that the configuration of the new network is suitable, the sealed network secrets can be restored and the previous private transactions replayed.

.. note:: Before attempting to recover a network, it is recommended to make a copy of all available ledgers and sealed secrets file.

Phase 1: Crash-fault tolerant public network
--------------------------------------------

To initiate the first phase of the recovery protocol, one of several nodes must be started with the ``--start=recover`` command line argument:

.. code-block:: bash

    $ cchost --start=recover --enclave-file=/path/to/application --node-address=node_ip:node_port --rpc-address=rpc_ip:rpc_port
    --ledger-file=ledger_file --node-cert-file=/path/to/node_certificate --quote-file=/path/to/quote

Each node will then immediately restore the public entries of its ledger (``--ledger-file``). Because deserialising the public entries present in the ledger may take some time, members are allowed to query the progress of the public recovery by running the ``getSignedIndex`` RPC which returns the version of the last signed recovered ledger entry. Once the public ledger is fully recovered, the ``getSignedIndex`` RPC returns ``{"state": "awaitingRecovery"}``.

Members are then allowed to send the new network configuration containing the properties of each node in the new network via the ``setRecoveryNodes`` RPC. The target node becomes the primary of the new network and applies the new network configuration. The new identity (``networkcert.pem`` public certificate) of the network is returned by the RPC command.

.. note:: It is recommended to submit the ``setRecoveryNodes`` RPC on the node that returns the highest ``"signed_index"`` to the ``getSignedIndex`` RPC. This way, the number of transactions recovered is maximised. Also note that some of most recent transactions executed before the network crashed may not be recovered as no signature certify their execution.

Similarly to the normal join protocol (see :ref:`Adding nodes to the network`), the initial set of nodes are then allowed to join the public network.

.. mermaid::

    sequenceDiagram
        participant Members
        participant Primary
        participant Backup

        Note over Primary, Backup: Started in recovery mode

        Members->>+Primary: getSignedIndex
        Primary-->>Members: {"signed_index": 50}
        Members->>Primary: getSignedIndex
        Primary-->>Members: {"state": "awaitingRecovery"}

        Note over Members: Choose the longest recovered ledger.

        Members->>+Primary: setRecoveryNodes RPC (new network configuration)

        Members->>+Backup: join network
        Backup->>+Primary: join network
        Backup-->>Members: join network response

        Note over Primary, Backup: Part of Public Network

Phase 2: Unsealing secrets and recovering private transactions
--------------------------------------------------------------

Once the public crash-fault tolerant network is established, members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery protocol. The first member proposes to recover the network and passes the sealed network secrets file to the new network:

.. code-block:: bash

    $ memberclient accept_recovery --sealed-secrets=/path/to/sealed/secrets/file --cert=/path/to/member1/cert --privk=/path/to/member1/private/key --server-address=primary_rpc_ip:primary_rpc_port --ca=/path/to/new/network/cert

If successful, this commands returns the proposal id that can be used by other members to submit their votes:

.. code-block:: bash

    $ ./memberclient vote --accept --cert=/path/to/member2/cert --privk=/path/to/member2/private/key --server-address=primary_rpc_ip:primary_rpc_port --id=proposal_id --ca=/path/to/new/network/cert

Once a quorum of members (defined by the constitution rules but typically, a majority of members) have agreed to recover the network, the network secrets are unsealed and the recovery of the private entries of the ledger is automatically started.

.. note:: While the primary and all active backups are recovering the private ledger, no new transaction can be executed by the network.

.. mermaid::

    sequenceDiagram
        participant Members
        participant Primary
        participant Backup

        Members->>+Primary: Propose recovery + sealed network secrets
        loop Wait until quorum
            Members->>+Primary: Vote(s)
        end

        Primary->>+Primary: Initiate end of recovery protocol

        Primary->>+Primary: Recover Private Ledger
        Backup->>+Backup: Recover Private Ledger

        Note over Primary: Part of Private Network
        Note over Backup: Part of Private Network

Once the recovery of the private ledger on all the nodes that have joined the new network is complete, the ledger is fully recovered and users are able to continue issuing business transactions.

.. warning:: After recovery, the identity of the network has changed. The new network certificate ``networkcert.pem`` returned in :ref:`Phase 1: Crash-fault tolerant public network` needs to be distributed to all existing and new users.

.. rubric:: Footnotes

.. [#sealing] `Intel SGX Sealing <https://software.intel.com/en-us/blogs/2016/05/04/introduction-to-intel-sgx-sealing>`_.
