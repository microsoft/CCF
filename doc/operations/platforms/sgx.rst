Intel SGX
===================

How to use the Intel SGX platform
---------------------------------
CCF must run on an Intel CPU which supports SGX.

To use SGX, set the enclave type in the :doc:`node configuration <../configuration>` to ``Release`` or ``Debug``.

Attestation
-----------
SGX attestations provide a measurement of the code loaded into the enclave, which CCF stores in the :ref:`audit/builtin_maps:``nodes.code_ids``` table. New nodes joining a network will provide their code id and the primary will perform an identity check against the table entries.

The first node in a new network will add its code id to the table. Members can then manage which code ids are present in the table with the ``add_node_code`` and ``remove_node_code`` actions.

Once the proposal has been accepted, nodes running the new code are authorised to join the network. Nodes running older versions of the code can then be retired and stopped.

.. note:: The identity of the code (``mrenclave``) can be found by running the ``oesign`` utility provided by :term:`Open Enclave` :

    .. code-block:: bash

        $ /opt/openenclave/bin/oesign dump -e enclave_library
        === Entry point:
        name=_start
        address=000000000097fa38

        === SGX Enclave Properties:
        product_id=1
        security_version=1
        debug=1
        xfrm=0
        num_heap_pages=50000
        num_stack_pages=1024
        num_tcs=8
        mrenclave=3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9
