Build CCF Applications
======================

.. note:: Before building a CCF application, make sure that CCF is installed (see :doc:`/build_apps/install_bin`).

Once an application is complete, it needs to be built into a shared object.

Using ``cmake``, an application can be built using the functions provided by CCF's ``cmake/ccf_app.cmake``. For example, for the ``js_generic`` JavaScript application:

.. literalinclude:: ../../CMakeLists.txt
    :language: cmake
    :start-after: SNIPPET_START: JS generic application
    :end-before: SNIPPET_END: JS generic application

Applications which share source files can compile them once with
``add_ccf_app(common OBJECT SRCS ...)`` and pass
``$<TARGET_OBJECTS:common>`` in each executable's ``SRCS`` list. The object
target uses the same warning, sanitizer, hardening, clang-tidy and coverage
settings as application targets. Keep variant-specific implementations, such
as overrides of ``ccf::get_ledger_sign_mode()``, in the executable's sources.