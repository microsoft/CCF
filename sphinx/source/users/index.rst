Using CCF Applications
======================

To generate the certificate and private key of trusted users should be generated as follows. For example, for one user:

.. code-block:: bash

    $ CCF/tests/keygenerator.sh user1
    Curve: secp384r1
    Generating private key and certificate for participant "user1"...
    Certificate generated at: user1_cert.pem (to be registered in CCF)
    Private key generated at: user1_privk.pem

.. note:: See :ref:`developers/cryptography:Algorithms and Curves` for the list of supported cryptographic curves.

Before issuing business transactions to CCF, the certificates of trusted users need to be voted in by the consortium of members (see :ref:`members/open_network:Adding Users`).

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    deploy_app
    issue_commands
    client
    rpc_api