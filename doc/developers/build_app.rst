Build and Sign Application
==========================

Once an application is complete, it needs to be built into a shared object, and signed.

Using `cmake`, an application can be built and then signed using the functions provided by CCF's ``CCF/cmake/ccf.cmake``. For example, for the ``lua_generic`` application:

.. literalinclude:: ../../cmake/common.cmake
    :language: cmake
    :start-after: SNIPPET_START: Lua generic application
    :end-before: SNIPPET_END: Lua generic application

The :term:`Open Enclave` configuration file (``oe_sign.conf``) should be placed under the same directory as the source files for the application. For example:

.. literalinclude:: ../../src/apps/logging/oe_sign.conf

.. note:: The `Open Enclave documentation <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-the-enclave>`_ provides details about the enclave settings in the ``oe_sign.conf`` configuration file.

Standalone Signing
------------------

It is also possible to sign an existing enclave application (e.g. ``liblua_generic.enclave.so``) manually, using a personal signing key (specified by ``--key-file``):

.. code-block:: bash

    $ /opt/openenclave/bin/oesign sign --enclave-image liblua_generic.enclave.so  --config-file CCF/src/apps/lua_generic/oe_sign.conf --key-file CCF/src/apps/sample_key.pem
    Created liblua_generic.enclave.so.signed
    $ ls *.so.signed
    liblua_generic.enclave.so.signed

It is then possible to inspect the signed enclave library:

.. code-block:: bash

    $ /opt/openenclave/bin/oesign dump --enclave-image liblua_generic.enclave.so.signed
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

:ref:`Operators should start each CCF node <operators/start_network:Starting the First Node>` with the signed enclave application as enclave file. For example, for the ``lua_generic`` application:

.. code-block:: bash

    $ cchost --enclave-file liblua_generic.signed.so [args]

.. note:: When deploying the ``lua_generic`` application, members should also :ref:`register the Lua application <members/open_network:Registering the Lua Application>` before the network is opened to users.

Debugging
---------

To connect a debugger to a CCF node, the configuration passed to `oesign sign` must have debugging enabled  (``Debug=1``). This should be disabled for production enclaves, to ensure confidentiality is maintained. If using the ``sign_app_library`` function defined in ``ccf_app.cmake``, 2 variants will be produced for each enclave. ``name.enclave.so.debuggable`` will have debugging enabled (meaning a debugger may be attached - the optimisation level is handled indepdently), while ``name.enclave.so.signed`` produces a final debugging-disabled enclave. The produced binaries are otherwise identical.

Additionally, the `cchost` binary must be told that the enclave type is debug:

.. code-block:: bash

    $ cchost --enclave-file liblua_generic.enclave.so.debuggable --enclave-type debug [args]

Build Container
---------------

With every release of CCF, a base build container is provided to facilitate reproducible builds and continuous integration.
It contains everything needed to build and test CCF applications.

.. literalinclude:: ../../docker/app_ci
   :language: dockerfile

The pre-built container can be obtained from `ccfciteam/ccf-app-ci <https://hub.docker.com/r/ccfciteam/ccf-app-ci>`_ on hub.docker.com.

.. code-block:: bash

    docker pull ccfciteam/ccf-app-ci:latest # Latest CCF release
    docker pull ccfciteam/ccf-app-ci:X.YZ   # Specific CCF release