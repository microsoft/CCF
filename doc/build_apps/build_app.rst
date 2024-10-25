Build CCF Applications
======================

.. note:: Before building a CCF application, make sure that CCF is installed (see :doc:`/build_apps/install_bin`).

Once an application is complete, it needs to be built into a shared object.

Using ``cmake``, an application can be built using the functions provided by CCF's ``cmake/ccf_app.cmake``. For example, for the ``js_generic`` JavaScript application:

.. literalinclude:: ../../CMakeLists.txt
    :language: cmake
    :start-after: SNIPPET_START: JS generic application
    :end-before: SNIPPET_END: JS generic application