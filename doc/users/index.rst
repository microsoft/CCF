Using Apps
==========

To generate the certificate and private key of trusted users should be generated as follows. For example, for one user:

.. code-block:: bash

    $ CCF/tests/keygenerator.sh --name user1
    -- Generating identity private key and certificate for participant "user1"...
    Identity private key generated at:   user1_privk.pem
    Identity certificate generated at:   user1_cert.pem (to be registered in CCF)

.. note:: See :ref:`developers/cryptography:Algorithms and Curves` for the list of supported cryptographic curves.

Before issuing business transactions to CCF, the certificates of trusted users need to be voted in by the consortium of members (see :ref:`members/open_network:Adding Users`).

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    deploy_app
    issue_commands
    rpc_api