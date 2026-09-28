Build CCF Applications
======================

.. note:: Before building a CCF application, make sure that CCF is installed (see :doc:`/build_apps/install_bin`).

Native applications are built into executables using the functions provided by CCF's ``cmake/ccf_app.cmake``; Rust applications use ``add_ccf_rust_app``, described in :doc:`example_rust`.

For example, for the ``js_generic`` JavaScript application:

.. literalinclude:: ../../CMakeLists.txt
    :language: cmake
    :start-after: SNIPPET_START: JS generic application
    :end-before: SNIPPET_END: JS generic application