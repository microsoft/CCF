Setup CCF Runtime Environment
=============================

Environment Setup
-----------------

First, checkout the CCF repository or :doc:`/build_apps/install_bin`.

Then, to quickly set up the dependencies necessary to start CCF applications, simply run:

.. code-block:: bash

    $ cd <ccf_path>/getting_started/setup_vm
    $ ./run.sh driver.yml # Only on SGX-enabled hardware
    $ ./run.sh app-run.yml

Runtime Container
-----------------

The ``ccfciteam/ccf-app-run`` container can be run to setup an environment containing the ``cchost`` binary (as per the `latest release of CCF <https://github.com/microsoft/CCF/releases/latest>`_) and the associated dependencies.

The pre-built container can be obtained from `ccfciteam/ccf-app-run <https://hub.docker.com/r/ccfciteam/ccf-app-run>`_ on hub.docker.com.

.. code-block:: bash

   $ docker pull ccfciteam/ccf-app-run:latest # Latest CCF release
   $ docker pull ccfciteam/ccf-app-run:X.YZ   # Specific CCF release

The container does not contain any particular CCF enclave application, and may be helpful when deploying CCF nodes via docker, k8s, etc. It is up to the operator(s) to mount the appropriate CCF enclave application and start and manage the CCF node.

.. note:: That image is optimised for size above all. If you need an image that comes with peripheral utilities, you probably want the :ref:`Build Container <build_apps/build_setup:Build Container>` instead.