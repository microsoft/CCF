Opening a Network
=================

This sections assumes that a set of nodes has already been started by :term:`Operators`. See :doc:`/operations/start_network`.


Adding Users
------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to :term:`Users`. First, the identities of trusted users should be generated, see :ref:`governance/adding_member:Generating Member Keys and Certificates`.

Then, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``cert`` is the PEM certificate of the user -- see :ref:`architecture/cryptography:Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ cat set_user.json
    {
        "actions": [
            {
                "name": "set_user",
                "args": {
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIBs...<SNIP>...yR\n-----END CERTIFICATE-----\n"
                }
            }
        ]
    }

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type proposal --ccf-gov-msg-created_at `date -Is` --signing-key member0_privk.pem --signing-cert member0_cert.pem --content set_user.json | \
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 0,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --signing-key member0_privk.pem --signing-cert member0_cert.pem --data-binary @set_user.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member. They may submit an unconditional approval, or their vote may query the current state and the proposed actions. These votes `must` be signed.

.. code-block:: bash

    $ cat vote_accept.json
    {
        "ballot": "export function vote (proposal, proposerId) { return true }"
    }

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253 --signing-key member0_privk.pem --signing-cert member0_cert.pem --content vote_accept.json | \
      curl https://<ccf-node-address>/gov/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 1,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/ballots --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @vote_accept.json -H "content-type: application/json"
    {
        "ballot_count": 1,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

    $ cat vote_conditional.json
    {
        "ballot": "export function vote (proposal, proposerId) { return proposerId == \"2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0\" }"
    }

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253 --signing-key member0_privk.pem --signing-cert member0_cert.pem --content vote_conditional.json | \
      curl https://<ccf-node-address>/gov/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 2,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253/ballots --cacert service_cert.pem --signing-key member2_privk.pem --signing-cert member2_cert.pem --data-binary @vote_conditional.json -H "content-type: application/json"
    {
        "ballot_count": 2,
        "proposal_id": "f665047e3d1eb184a7b7921944a8ab543cfff117aab5b6358dc87f9e70278253",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Accepted"
    }

The user is successfully added once the proposal has received enough votes under the rules of the :term:`Constitution` (indicated by the response body showing a transition to state ``Accepted``).

The user can then make user RPCs.

User Data
---------

For each user, CCF also stores arbitrary user-data in a JSON object. This can only be written to by members, subject to the standard proposal-vote governance mechanism, via the ``set_user_data`` action. This lets members define initial metadata for certain users; for example to grant specific privileges, associate a human-readable name, or categorise the users. This user-data can then be read (but not written) by user-facing endpoints.

For example, the ``/log/private/admin_only`` endpoint in the C++ logging sample app uses user-data to restrict who is permitted to call it:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: user_data_check
    :end-before: SNIPPET_END: user_data_check
    :dedent:

Members configure this permission with ``set_user_data`` proposals:

.. code-block:: bash

    $ cat set_user_data_proposal.json
    {
        "actions": [
            {
                "name": "set_user_data",
                "args": {
                    "user_id": "529d0f48287923e7536a708c0b7747666f6b904d3fd4b84739f7d2204233a16e",
                    "user_data": {
                        "isAdmin": true
                    }
                }
            }
        ]
    }


Once this proposal is accepted, the newly added user (with ID ``529d0f48287923e7536a708c0b7747666f6b904d3fd4b84739f7d2204233a16e``) is able to use this endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/app/log/private/admin_only --key user0_privk.pem --cert user0_cert.pem --cacert service_cert.pem -X POST --data-binary '{"id": 42, "msg": "hello world"}' -H "Content-type: application/json" -i
    HTTP/1.1 200 OK

    true

All other users have empty or non-matching user-data, so will receive a HTTP error if they attempt to access it:

.. code-block:: bash

    $ curl https://<ccf-node-address>/app/log/private/admin_only --key user1_privk.pem --cert user1_cert.pem --cacert service_cert.pem -X POST --data-binary '{"id": 42, "msg": "hello world"}' -H "Content-type: application/json" -i
    HTTP/1.1 403 Forbidden

    {"error":{"code":"AuthorizationFailed","message":"Only admins may access this endpoint."}}

Opening the Network
-------------------

Once users are added to the opening network, members should create a proposal to open the network:

.. code-block:: bash

    $ cat transition_service_to_open.json
    {
        "actions": [
            {
                "name": "transition_service_to_open",
                "args": {                 
                    "next_service_identity": "-----BEGIN CERTIFICATE-----\nMIIBezCCASGgAwIBAgIRAOVHYf9qhvjzdoIw3fPHp5YwCgYIKoZIzj0EAwIwFjEU\nMBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwMzExMTcwNTQzWhcNMjIwMzEyMTcw\nNTQyWjAWMRQwEgYDVQQDDAtDQ0YgTmV0d29yazBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABBZXMHCrjfBeO+FHqDG8Szjzc4lQC8KmvTX8Il0ZERXH/mjLZ7Dc52rX\nnilD1ghdRDWXiKMQWT9RPvm4tefWHD6jUDBOMAwGA1UdEwQFMAMBAf8wHQYDVR0O\nBBYEFCUmm9u05D0/IFupggFW5VgVlUSyMB8GA1UdIwQYMBaAFCUmm9u05D0/IFup\nggFW5VgVlUSyMAoGCCqGSM49BAMCA0gAMEUCIQCy6WoeLtTUD8GRIOM+oRNe/lTj\nRrrry+0AxZgxBU1oSwIgJmyrTfT90re+rzAkF9uiqoL44TVWkQf1t3cZrgVFYK8=\n-----END CERTIFICATE-----\n"
                }
            }
        ]
    }

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type proposal --ccf-gov-msg-created_at `date -Is` --signing-key member0_privk.pem --signing-cert member0_cert.pem --content transition_service_to_open.json | \
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 0,
        "proposal_id": "77374e16de0b2d61f58aec84d01e6218205d19c9401d2df127d893ce62576b81",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --signing-key member0_privk.pem --signing-cert member0_cert.pem --data-binary @transition_service_to_open.json -H "content-type: application/json"
    {
        "ballot_count": 0,
        "proposal_id": "77374e16de0b2d61f58aec84d01e6218205d19c9401d2df127d893ce62576b81",
        "proposer_id": "2af6cb6c0af07818186f7ef7151061174c3cb74b4a4c30a04a434f0c2b00a8c0",
        "state": "Open"
    }

Other members are then able to vote for the proposal using the returned proposal id.

Once the proposal has received enough votes under the rules of the :term:`Constitution` (ie. ballots which evaluate to ``true``), the network is opened to users. It is only then that users are able to execute transactions on the business logic defined by the enclave file (``enclave.file`` configuration entry).
