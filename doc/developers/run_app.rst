
Running CCF Applications
========================

.. note:: For a quick and easy way to run a CCF application locally, try :doc:`/quickstart/test_network`, specifying the desired enclave image.

Debugging
---------

To connect a debugger to a CCF node, the configuration passed to ``oesign sign`` must have debugging enabled  (``Debug=1``). This `must` be disabled for production enclaves, to ensure confidentiality is maintained. If using the ``sign_app_library`` function defined in ``ccf_app.cmake``, two variants will be produced for each enclave. ``name.enclave.so.debuggable`` will have debugging enabled (meaning a debugger may be attached - the optimisation level is handled independently), while ``name.enclave.so.signed`` produces a final debugging-disabled enclave. The produced binaries are otherwise identical.

Additionally, the ``cchost`` binary must be told that the enclave type is debug:

.. code-block:: bash

    $ cchost --enclave-file liblua_generic.enclave.so.debuggable --enclave-type debug [args]