Runtime Container
=================

With every release, a sample runtime base container is provided. It contains the ``cchost`` executable and its dependencies,
but no particular enclave file, and may be helpful when deploying CCF nodes via docker, k8s etc.

That image is optimised for size above all. If you need an image that comes with peripheral utilities,
you probably want the :doc:`Build Container <developers/build_app>` instead.

Dockerfile
----------

.. literalinclude:: ../../docker/app_run
   :language: dockerfile

Container
---------

The pre-built container can be obtained from `ccfciteam/ccf-app-run <https://hub.docker.com/r/ccfciteam/ccf-app-run>`_ on hub.docker.com.

.. code-block:: bash

    docker pull ccfciteam/ccf-app-run:latest # Latest CCF release
    docker pull ccfciteam/ccf-app-run:X.YZ   # Specific CCF release