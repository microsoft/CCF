Build CCF Applications
======================

.. note:: Before building a CCF application, make sure that CCF is installed (see :doc:`/build_apps/install_bin`).

Native applications are built into executables. For Rust, follow
:doc:`example_rust`, which uses ``add_ccf_rust_app`` to link a Rust static
library with CCF's native bridge and launcher.

Using ``cmake``, an application can be built using the functions provided by CCF's ``cmake/ccf_app.cmake``. For example, for the ``js_generic`` JavaScript application:

.. literalinclude:: ../../CMakeLists.txt
    :language: cmake
    :start-after: SNIPPET_START: JS generic application
    :end-before: SNIPPET_END: JS generic application