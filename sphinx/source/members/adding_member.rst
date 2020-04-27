Adding New Members
==================

It is possible for existing members to add new members to the consortium after a CCF network has been started.

.. note:: The maximum number of active consortium members at any given time is 255.

Generating Member Keys and Certificate
--------------------------------------

First, the identity and encryption public and private key pairs of the new member should be created.

The ``keygenerator.sh`` script can be used to generate the member’s certificate and associated private key as well as their encryption public and private keys.

.. code-block:: bash

    $ keygenerator.sh --name=member_name --gen-enc-key
    -- Generating identity private key and certificate for participant "member_name"...
    Identity curve: secp384r1
    Identity private key generated at:   member_name_privk.pem
    Identity certificate generated at:   member_name_cert.pem (to be registered in CCF)
    -- Generating encryption key pair for participant "member_name"...
    Encryption private key generated at:  member_name_enc_priv.pem
    Encryption public key generated at:   member_name_enc_pub.pem (to be registered in CCF)

The member’s private keys (e.g. ``member_name_privk.pem`` and ``member_name_enc_priv.pem``) should be stored on a trusted device while the certificate (e.g. ``member_name_cert.pem``) and public encryption key (e.g. ``member_name_enc_pub.pem``) should be registered in CCF by members.

.. note:: See :ref:`developers/cryptography:Algorithms and Curves` for the list of supported cryptographic curves for member identity.

Registering a New Member
------------------------

Once the new member's keys and certificate have been generated, the existing consortium should register the new member public information in CCF, following the usual propose and vote procedure.

The :ref:`members/proposals:Submitting a New Proposal` section describes the steps that members should follow to register a new member.

Activating a New Member
-----------------------

A new member who gets registered in CCF is not yet able to participate in governance operations. To do so, the new member should first acknowledge that they are satisfied with the state of the service (for example, after auditing the current constitution and the nodes currently trusted).

First, the new member should update and retrieve the latest state digest via the ``members/updateAckStateDigest`` command. In doing so, the new member confirms that they are satisfied with the current state of the service.

.. code-block:: bash

    $ curl https://<ccf-node-address>/members/updateAckStateDigest  --cacert networkcert.pem --key new_member_privk.pem --cert new_member_cert.pem
    {
        "state_digest": <...>
    }


Then, the new member should sign the state digest returned by the ``members/updateAckStateDigest`` via the ``members/ack`` command, using the ``scurl.sh`` utility:

.. code-block:: bash

    $ ./scurl.sh https://<ccf-node-address>/members/ack  --cacert networkcert.pem --key new_member_privk.pem --cert new_member_cert.pem --header "Content-Type: application/json" --data-binary '{"state_digest": <...>}'
    true

Once the command completes, the new member becomes active and can take part in governance operations (e.g. creating a new proposal or voting for an existing one).

.. note:: The newly-activated member is also given a recovery share that can be used :ref:`to recover a defunct service <members/accept_recovery:Submitting Recovery Shares>`.