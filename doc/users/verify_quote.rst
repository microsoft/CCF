Verifing Quote
==============

A client can verify the SGX quote of the CCF node that it connects to.

First, the client should connect to the node to verify, specifying the ``/node/quote`` endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quote --cacert networkcert.pem
    {"quotes": [{"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"}]}

The raw quote should be decoded and output to file for verification via the Open Enclave ``host_verify`` command-line utility:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quote --cacert networkcert.pem | jq .quotes[0].raw | xxd -r -p > ccf_node_quote.bin

    $ /opt/openenclave/bin/host_verify -r ccf_node_quote.bin
    Verifying report ccf_node_quote.bin...
    Report verification succeeded (0).

.. note:: The ``host_verify`` CLI is included in the Open Enclave ``hostverify`` package available on the `Open Enclave release page <https://github.com/openenclave/openenclave/releases>`_.

The SGX quotes of all currently trusted nodes can also be retrieved via the ``/node/quotes`` endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quotes --cacert networkcert.pem
    {"quotes": [
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"},
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"}]}
