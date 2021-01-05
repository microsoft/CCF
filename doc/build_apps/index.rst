Build Apps
==========

This section describes how CCF applications can be developed and deployed to a CCF network.

Applications can be written in JavaScript/TypeScript or C++. An application consists of a collection of endpoints that can be triggered by :term:`Users`. Each endpoint can define an :ref:`build_apps/logging_cpp:API Schema` to validate user requests.

These endpoints can read or mutate the state of a unique :ref:`build_apps/kv/index:Key-Value Store` that represents the internal state of the application. Applications define a set of ``Maps`` (see :ref:`build_apps/kv/kv_how_to:Creating a Map`), mapping from a key to a value. When an application endpoint is triggered, the effects on the Store are committed atomically.

.. panels::

    :fa:`cloud` :doc:`create_vm`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Create a SGX-enabled Azure Virtual Machine.

    ---

    :fa:`download` :doc:`install_bin`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Install CCF on Linux.

    ---

    :fa:`laptop-code` :doc:`build_setup`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Setup CCF environment to build CCF apps.

    ---

    .. image:: ../img/cpp.svg
      :width: 22
      :alt: C++
      :align: left

    :doc:`example`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Sample CCF application written in C++.

    ---

    .. image:: ../img/ts.svg
      :width: 22
      :alt: C++
      :align: left

    :doc:`js_app`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Sample CCF application written in TypeScript or JavaScript.

    ---

    :fa:`tools` :doc:`build_app`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Building a CCF application.

    ---

    :fa:`cogs` :doc:`run_app`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Running a CCF application in a sandbox environment for development.

    ---

    :fa:`rocket` :doc:`demo`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Running a CCF application demo from scratch.

    ---

    :fa:`users` :doc:`auth/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    User authentication mechanisms in CCF.

    ---

    :fa:`database` :doc:`kv/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Transactional access to state is provided by the Key-Value store.

    ---

    :fa:`external-link-alt` :doc:`upgrading_app`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Application upgrade in CCF.

    ---

    :fa:`terminal` :doc:`api`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    C++ API reference.

.. toctree::
    :hidden:

    create_vm
    install_bin
    build_setup
    example
    js_app
    build_app
    run_app
    demo
    auth/index
    kv/index
    upgrading_app
    api