Install CCF
===========

Requirements
------------

CCF builds and runs on Linux. It is primarily developed and tested on Ubuntu 18.04.
Running CCF with full security guarantees requires :term:`SGX` hardware with :term:`FLC`.

.. note::

    A `virtual` version of CCF can also be run on hardware that does not support SGX. The `virtual` mode provides no security guarantee and is only useful for development and prototyping.

CCF requires the following dependencies to be first installed on your system:

- :term:`Intel SGX PSW`
- :term:`Azure DCAP`
- :term:`Open Enclave`

These dependencies can be conveniently installed using the ``ansible`` playbooks in the CCF repository or `Install`_:

.. code-block:: bash

    $ cd <ccf_path>/getting_started/setup_vm/
    $ ./run.sh driver.yml # Only on SGX-enabled hardware
    $ ./run.sh app-run.yml

Install
-------

CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases/latest>`_.

The CCF Debian package (``ccf_<version>_amd64.deb``) contains the libraries and utilities to start a CCF service and build CCF applications. CCF can be installed as follows:

.. code-block:: bash

    $ export CCF_VERSION=0.14.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_VERSION}_amd64.deb
    $ sudo apt install ./ccf_${CCF_VERSION}_amd64.deb

Assuming that CCF was installed under ``/opt``, the following commands can be run to verify that CCF was installed successfully:

.. code-block:: bash

    $ /opt/ccf-${CCF_VERSION}/bin/cchost --version
    CCF host: ccf-<version>

    $ /opt/ccf-${CCF_VERSION}/bin/sandbox.sh
    No package/app specified. Defaulting to installed JS logging app
    Setting up Python environment...
    Python environment successfully setup
    [16:10:16.552] Starting 1 CCF node...
    [16:10:16.552] Virtual mode enabled
    [16:10:23.349] Started CCF network with the following nodes:
    [16:10:23.350]   Node [0] = https://127.0.0.1:8000
    ...

The CCF install notably contains:

- The ``cchost`` binary required to spin up a CCF application
- The ``cmake`` files required to build CCF applications
- Azure and ``ansible`` scripts required to :doc:`create_vm` and :doc:`build_setup` (under ``getting_started/``)
- Header files and libraries to build CCF applications (under ``include/`` and ``lib/``)
- A limited set of Python utilities to start a basic CCF service for local testing
- Various utility scripts (see :doc:`/build_apps/demo`)

Uninstall
---------

To remove an installation of CCF, run:

.. code-block:: bash

    $ sudo apt remove ccf