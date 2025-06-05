Adding New Members
==================

It is possible for existing members to add new members to the consortium after a CCF network has been started.

Generating Member Keys and Certificates
---------------------------------------

.. note:: See :doc:`/governance/hsm_keys` for a guide on how to used member keys and certificate store in Azure Key Vault.

First, the identity and encryption public and private key pairs of the new member should be created.

The ``keygenerator.sh`` script can be used to generate the member’s certificate and associated private key as well as their encryption public and private keys.
It is included in the `ccf` Python package, and the `.rpm` package will install it under `/opt/ccf_*/bin/`.

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
    7f46110b62ccbbd5f18b4c9bda876024399fd538133f8c26d4bfe5a9d80e59e6

.. note:: See :ref:`architecture/cryptography:Algorithms and Curves` for the list of supported cryptographic curves for member identity.

Registering a New Member
------------------------

Once the new member's keys and certificate have been generated, the existing consortium should register the new member public information in CCF, following the usual propose and vote procedure.

The :ref:`governance/proposals:Submitting a New Proposal` section describes the steps that members should follow to register a new member.

Activating a New Member
-----------------------

.. note:: The `ccf_cose_sign1` script is distributed in the `ccf` Python package, available on PyPI. It can be installed with `pip install ccf`.

A new member who gets registered in CCF is not yet able to participate in governance operations. To do so, the new member should first acknowledge that they are satisfied with the state of the service (for example, after auditing the current constitution and the nodes currently trusted).

First, the new member should update and retrieve the latest state digest via the :http:POST:`/gov/members/state-digests/{memberId}:update` endpoint. In doing so, the new member confirms that they are satisfied with the current state of the service.

.. code-block:: bash

    $ touch empty_file
    $ ccf_cose_sign1 \
      --ccf-gov-msg-type state_digest \
      --ccf-gov-msg-created_at `date -uIs` \
      --signing-key new_member_privk.pem \
      --signing-cert new_member_cert.pem \
      --content empty_file \ # Note that passing an empty file is required
    | curl https://<ccf-node-address>/gov/members/state-digests/7f46110b62ccbbd5f18b4c9bda876024399fd538133f8c26d4bfe5a9d80e59e6:update?api-version=2024-07-01 \
      -X POST \
      --cacert service_cert.pem \
      --key new_member_privk.pem \
      --cert new_member_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose" \
      --silent | jq > request.json
    $ cat request.json
    {
        "digest": <...>
    }


Then, the new member should sign the state digest returned by :http:POST:`/gov/members/state-digests/{memberId}:update` (or :http:GET:`/gov/members/state-digests/{memberId}`) via the :http:POST:`/gov/members/state-digests/{memberId}:ack` endpoint, using the ``ccf_cose_sign1`` utility:

.. code-block:: bash

    $ ccf_cose_sign1 \
      --ccf-gov-msg-type ack \
      --ccf-gov-msg-created_at `date -uIs` \
      --signing-key new_member_privk.pem \
      --signing-cert new_member_cert.pem \
      --content request.json \
    | curl https://<ccf-node-address>/gov/members/state-digests/7f46110b62ccbbd5f18b4c9bda876024399fd538133f8c26d4bfe5a9d80e59e6:ack?api-version=2024-07-01 \
      --cacert service_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose"

Once the command completes, the new member becomes active and can take part in governance operations (e.g. creating a new proposal or voting for an existing one). You can verify the activation of the member at :http:GET:`/gov/service/members/{memberId}`.

.. code-block:: bash

    $ curl https://<ccf-node-address>/gov/service/members/7f46110b62ccbbd5f18b4c9bda876024399fd538133f8c26d4bfe5a9d80e59e6?api-version=2024-07-01 --silent | jq
    {
        "memberId": "7f46110b62ccbbd5f18b4c9bda876024399fd538133f8c26d4bfe5a9d80e59e6",
        "certificate": <...>,
        "memberData": <...>,
        "status": "Active"
    }

.. note:: The newly-activated member is also given a recovery share that can be used :ref:`to recover a defunct service <governance/accept_recovery:Submitting Recovery Shares>`.
