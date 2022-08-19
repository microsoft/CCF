Adding New Members
==================

It is possible for existing members to add new members to the consortium after a CCF network has been started.

.. note:: The maximum number of allowed active recovery members (i.e. those with a recovery share) at any given time is 255.

Generating Member Keys and Certificates
---------------------------------------

.. note:: See :doc:`/governance/hsm_keys` for a guide on how to used member keys and certificate store in Azure Key Vault.

First, the identity and encryption public and private key pairs of the new member should be created.

The ``keygenerator.sh`` script can be used to generate the member’s certificate and associated private key as well as their encryption public and private keys.

.. code-block:: bash

    $ keygenerator.sh --name member_name [--gen-enc-key]
    -- Generating identity private key and certificate for participant "member_name"...
    Identity curve: secp384r1
    Identity private key generated at:   member_name_privk.pem
    Identity certificate generated at:   member_name_cert.pem (to be registered in CCF)
    # Only if --gen-enc-key is used:
    -- Generating RSA encryption key pair for participant "member_name"...
    Encryption private key generated at:  member_name_enc_privk.pem
    Encryption public key generated at:   member_name_enc_pubk.pem (to be registered in CCF)

Members that are registered in CCF `with` a public encryption key are recovery members. Each recovery member is given a recovery share (see :ref:`governance/accept_recovery:Submitting Recovery Shares`) that can be used to recover a defunct service. Members registered `without` a public encryption key are not given recovery shares and cannot recover the defunct service.

The member’s identity and encryption private keys (e.g. ``member_name_privk.pem`` and ``member_name_enc_privk.pem``) should be stored on a trusted device (e.g. HSM) while the certificate (e.g. ``member_name_cert.pem``) and public encryption key (e.g. ``member_name_enc_pubk.pem``) should be registered in CCF by members.

The CCF unique member identity is the hex-encoded string of the SHA-256 hash of the DER-encoded certificate, and can be computed from the certificate alone, without interacting with CCF:

.. code-block:: bash

    $ identity_cert_path=/path/to/member/cert
    $ openssl x509 -in "$identity_cert_path" -noout -fingerprint -sha256 | cut -d "=" -f 2 | sed 's/://g' | awk '{print tolower($0)}'

.. note:: See :ref:`architecture/cryptography:Algorithms and Curves` for the list of supported cryptographic curves for member identity.

Registering a New Member
------------------------

Once the new member's keys and certificate have been generated, the existing consortium should register the new member public information in CCF, following the usual propose and vote procedure.

The :ref:`governance/proposals:Submitting a New Proposal` section describes the steps that members should follow to register a new member.

Activating a New Member
-----------------------

A new member who gets registered in CCF is not yet able to participate in governance operations. To do so, the new member should first acknowledge that they are satisfied with the state of the service (for example, after auditing the current constitution and the nodes currently trusted).

First, the new member should update and retrieve the latest state digest via the :http:POST:`/gov/ack/update_state_digest` endpoint. In doing so, the new member confirms that they are satisfied with the current state of the service.

.. code-block:: bash

    $ curl https://<ccf-node-address>/gov/ack/update_state_digest -X POST --cacert service_cert.pem --key new_member_privk.pem --cert new_member_cert.pem --silent | jq > request.json
    $ cat request.json
    {
        "state_digest": <...>
    }


Then, the new member should sign the state digest returned by the :http:POST:`/gov/ack/update_state_digest` via the :http:POST:`/gov/ack` endpoint, using the ``scurl.sh`` utility:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/ack  --cacert service_cert.pem --signing-key new_member_privk.pem --signing-cert new_member_cert.pem --header "Content-Type: application/json" --data-binary @request.json
    true

Once the command completes, the new member becomes active and can take part in governance operations (e.g. creating a new proposal or voting for an existing one). You can verify the activation of the member at `/gov/members`.

.. code-block:: bash

    $ curl https://<ccf-node-address>/gov/members --silent | jq
    {
        "<member_id>": {
            "cert": <...>,
            "member_data": <...>,
            "public_encryption_key": <...>,
            "status": "Active"
        }
    }

.. note:: The newly-activated member is also given a recovery share that can be used :ref:`to recover a defunct service <governance/accept_recovery:Submitting Recovery Shares>`.
