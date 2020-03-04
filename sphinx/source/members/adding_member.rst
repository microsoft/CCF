Adding New Members
==================

It is possible for existing members to add new members to the consortium after a CCF network has been started.

Generating Member Keys and Certificate
--------------------------------------

First, the identity and key share public and private key pairs of the new member should be created.

The ``keygenerator.sh`` script can be used to generate the member’s certificate and associated private key as well as their key share public and private keys.

.. code-block:: bash

    $ keygenerator.sh --name=member_name --gen-key-share
    -- Generating identity private key and certificate for participant "member_name"...
    Identity curve: secp384r1
    Identity certificate generated at:   member_name_cert.pem (to be registered in CCF)
    Identity private key generated at:   member_name_privk.pem
    -- Generating key share pair for participant "member_name"...
    Key share public key generated at:   member_name_kshare_pub.pem (to be registered in CCF)
    Key share private key generated at:  member_name_kshare_priv.pem

The member’s private keys (e.g. ``member_name_privk.pem`` and ``member_name_kshare_priv.pem``) should be stored on a trusted device while the certificate (e.g. ``member_name_cert.pem``) and public key share (e.g. ``member_name_kshare_pub.pem``) should be registered in CCF by members.

.. note:: See :ref:`developers/cryptography:Algorithms and Curves` for the list of supported cryptographic curves for member identity.

Registering a New Member
------------------------

Once the new member's keys and certificate have been generated, the existing consortium should register the new member public information in CCF, following the usual propose and vote procedure.

The :ref:`members/proposals:Submitting a New Proposal` section describes the steps that members should follow to register a new member.

Activating a New Member
-----------------------

A new member who gets registered in CCF is not yet able to participate in governance operations. To do so, the new member should first acknowledge that they are satisfied with the state of the service (for example, after auditing the current constitution and the nodes currently trusted).

First, the new member should update and retrieve the latest state digest via the ``members/updateAckStateDigest`` command. In doing so, the new member confirms that they are satisfied with the state of the service.

.. code-block:: bash

    $ curl https://<ccf-node-address>/members/updateAckStateDigest  --cacert networkcert.pem --key new_member_privk.pem --cert new_member_cert.pem --header "Content-Type: application/json" --data '{"jsonrpc":"2.0", "id":0, "method":"members/updateAckStateDigest", "params":{}}'
    {"commit":57,"global_commit":56,"id":0,"jsonrpc":"2.0","result":[<state_digest>],"term":2}


Then, the new member should sign the state digest returned by the ``members/updateAckStateDigest`` via the ``members/ack`` command, using the ``scurl.sh`` utility:

.. code-block:: bash

    $ ./scurl.sh https://<ccf-node-address>/members/ack  --cacert networkcert.pem --key new_member_privk.pem --cert new_member_cert.pem --header "Content-Type: application/json" --data '{"jsonrpc":"2.0", "id":0, "method":"members/updateAck", "params":{"state_digest":"[<state_digest>]"}}'
    {"commit":59,"global_commit":58,"id":0,"jsonrpc":"2.0","result":True,"term":2}

Once the command completes, the new member becomes active and can take part in governance operations (e.g. creating a new proposal or voting for an existing one).