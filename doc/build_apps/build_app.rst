Build and Sign CCF Applications
===============================

.. note:: Before building a CCF application, make sure that:

    - The CCF development environment has successfully been setup (see :ref:`environment setup instructions <quickstart/build_setup:Setup CCF Development Environment>`).
    - CCF is installed (see :ref:`installation steps <quickstart/install:Install>`).

Once an application is complete, it needs to be built into a shared object, and signed.

Using `cmake`, an application can be built and then signed using the functions provided by CCF's ``cmake/ccf.cmake``. For example, for the ``js_generic`` JavaScript application:

.. literalinclude:: ../../cmake/common.cmake
    :language: cmake
    :start-after: SNIPPET_START: JS generic application
    :end-before: SNIPPET_END: JS generic application

The :term:`Open Enclave` configuration file (``oe_sign.conf``) should be placed under the same directory as the source files for the application. For example:

.. literalinclude:: ../../samples/apps/logging/oe_sign.conf

.. note:: The `Open Enclave documentation <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-an-SGX-enclave>`_ provides details about the enclave settings in the ``oe_sign.conf`` configuration file.

Standalone Signing
------------------

It is also possible to sign an existing enclave application (e.g. ``libjs_generic.enclave.so``) manually, using a signing key (specified by ``--key-file``):

.. code-block:: bash

    $ openssl genrsa -out signing_key.pem -3 3072
    $ /opt/openenclave/bin/oesign sign --enclave-image libjs_generic.enclave.so --config-file CCF/src/apps/js_generic/oe_sign.conf --key-file signing_key.pem
    Created libjs_generic.enclave.so.signed
    $ ls *.so.signed
    libjs_generic.enclave.so.signed

It is then possible to inspect the signed enclave library:

.. code-block:: bash

    $ /opt/openenclave/bin/oesign dump --enclave-image libjs_generic.enclave.so.signed
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

For a given application, the ``signature`` field depends on the key used to sign the enclave. See :ref:`governance/common_member_operations:Updating Code Version` for instructions on how members can register new application versions (``mrenclave`` field).

.. note:: The `Open Enclave documentation <https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md#signing-an-SGX-enclave>`_. provides further details about how to sign enclave applications using ``oesign``.
