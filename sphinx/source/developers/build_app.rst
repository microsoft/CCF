Build and Sign Application
==========================

Once an application is complete, it needs to be built into a shared object, and signed.

Using `cmake`, an application can be built and automatically signed using the ``add_enclave_lib`` function, provided by CCF's ``CCF/cmake/common.cmake``. For example, for the ``luageneric`` application:

.. literalinclude:: ../../../cmake/common.cmake
    :language: cmake
    :start-after: SNIPPET: Lua generic application
    :lines: 1

The :term:`Open Enclave` configuration file (``oe_sign.conf``) should be placed under the same directory as the source files for the application. For example:

.. literalinclude:: ../../../src/apps/logging/oe_sign.conf

.. note:: The `Open Enclave documentation <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-the-enclave>`_ provides details about the enclave settings in the ``oe_sign.conf`` configuration file.

Standalone Signing
------------------

It is also possible to sign an existing enclave application (e.g. ``libluagenericenc.so``) manually, using a personal signing key (specified by ``--key-file``):

.. code-block:: bash

    $ /opt/openenclave/bin/oesign sign --enclave-image libluagenericenc.so  --config-file CCF/src/apps/luageneric/oe_sign.conf --key-file CCF/src/apps/sample_key.pem
    Created libluagenericenc.so.signed
    $ ls *.so.signed
    libluagenericenc.so.signed

It is then possible to inspect the signed enclave library:

.. code-block:: bash

    $ /opt/openenclave/bin/oesign dump --enclave-image libluagenericenc.so.signed
    === Entry point:
    name=_start
    address=00000000008dee48

    === SGX Enclave Properties:
    product_id=1
    security_version=1
    debug=1
    xfrm=0
    num_heap_pages=32768
    num_stack_pages=1024
    num_tcs=8
    mrenclave=3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9
    signature=...

For a given application, the ``signature`` field depends on the key used to sign the enclave. See :ref:`members/common_member_operations:Updating Code Version` for instructions on how members can register new application versions (``mrenclave`` field).

.. note:: The `Open Enclave documentation <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-the-enclave>`_. provides further details about how to sign enclave applications using ``oesign``.

Running the Application
-----------------------

:ref:`Operators should start each CCF node <operators/start_network:Starting the First Node>` with the signed enclave application as enclave file. For example, for the ``luageneric`` application:

.. code-block:: bash

    $ cchost --enclave-file libluagenericenc.signed.so [args]

.. note:: When deploying the ``luageneric`` application, members should also :ref:`register the Lua application <members/open_network:Registering the Lua Application>` before the network is opened to users.
