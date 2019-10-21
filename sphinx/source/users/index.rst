Using CCF Applications
======================

To generate the certificate and private key of trusted users should be generated as follows. For example, for one user:

.. code-block:: bash

    $ keygenerator --name user1
    $ ls user1*
    user1_cert.pem user1_privk.pem

Before issuing business transactions to CCF, the certificates of trusted users need to be voted in by the consortium of members (see :ref:`Adding Users`).

Clients communicate with CCF using framed :term:`JSON-RPC` over :term:`TLS`.

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    issue_commands
    client
    rpc_api