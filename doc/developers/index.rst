Build Apps
==========

This section describes how CCF applications can be developed and deployed to a CCF network.

Applications can be written in JavaScript or C++. An application consists of a collection of endpoints that can be triggered by :term:`Users`. Each endpoint can define an :ref:`developers/logging_cpp:API Schema` to validate user requests.

These endpoints can read or mutate the state of a unique :ref:`developers/kv/index:Key-Value Store` that represents the internal state of the application. Applications define a set of ``Maps`` (see :ref:`developers/kv/kv_how_to:Creating a Map`), mapping from a key to a value. When an application endpoint is triggered, the effects on the Store are committed atomically.

.. panels::

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

    :fa:`hand-paper` :doc:`demo`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Running a CCF application demo from scratch.

    ---

    :fa:`hand-paper` :doc:`auth/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ---

    :fa:`hand-paper` :doc:`auth/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ---

    :fa:`hand-paper` :doc:`kv/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ---

    :fa:`hand-paper` :doc:`upgrading_app`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    ---

    :fa:`hand-paper` :doc:`api`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. toctree::
    :hidden:

    example
    js_app
    build_app
    run_app
    demo
    auth/index
    kv/index
    upgrading_app
    api