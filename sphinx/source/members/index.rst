Member Governance
=================

This section describes how a consortium of trusted :term:`members` governs an existing CCF network. It explains how members can submit proposals to CCF and how these proposals are accepted based on the rules defined in the :term:`constitution`.

Before creating a new CCF network, the identity of the initial member(s) of the consortium must be generated.

The ``CCF/tests/keygenerator.sh`` script can be used to generate the member's certificate and associated private key. For example, to generate the first member's certificate and private key:

.. code-block:: bash

    $ CCF/tests/keygenerator.sh --name=member1 --gen-encryption-key
    -- Generating identity private key and certificate for participant "member1"...
    Identity curve: secp384r1
    Identity certificate generated at:    member1_cert.pem (to be registered in CCF)
    Identity private key generated at:    member1_privk.pem
    -- Generating encryption key pair for participant "member1"...
    Encryption public key generated at:   member1_enc_pubk.pem (to be registered in CCF)
    Encryption private key generated at:  member1_enc_privk.pem

.. note:: See :ref:`developers/cryptography:Algorithms and Curves` for the list of supported cryptographic curves.

The member's private key (e.g. ``member1_privk.pem``) should be stored on a trusted device while the certificate (e.g. ``member1_cert.pem``) and public keyshare (e.g. ``member1_enc_pubk.pem``) should be given to operators before starting the first node of a new CCF network.


.. toctree::
    :maxdepth: 2
    :caption: Contents:

    constitution
    proposals
    open_network
    common_member_operations
    member_rpc_api



