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

Confidential Consortium Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The CCF Debian package (``ccf_<version>_amd64.deb``) contains the libraries and utilities to start a CCF service and build CCF applications. CCF can be installed as follows:

.. code-block:: bash

    $ export CCF_VERSION=0.14.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_VERSION}_amd64.deb
    $ sudo apt install ./ccf_${CCF_VERSION}_amd64.deb

Assuming that CCF was installed under ``/opt``, the following command can be run to verify that CCF was installed successfully:

.. code-block:: bash

    $ /opt/ccf-${CCF_VERSION}/bin/cchost --version
    CCF host: ccf-<version>

The CCF install notably contains:

- The ``cchost`` binary required to spin up a CCF application
- The ``cmake`` files required to build CCF applications
- Azure and ``ansible`` scripts required to :doc:`create_vm` and :doc:`build_setup` (under ``getting_started/``)
- Header files and libraries to build CCF applications (under ``include/`` and ``lib/``)
- A limited set of Python utilities to start a basic CCF service for local testing
- Various utility scripts

Python Package
~~~~~~~~~~~~~~

The CCF Python tools package can be used to interact with an existing running service and provides utilities to:

- Issue HTTP requests over TLS to CCF applications
- Build custom governance proposals and votes
- Parse and verify the integrity of a CCF ledger

The latest version of the CCF Python tools package is `available on PyPi <https://pypi.org/project/ccf/>`_ and can be installed as follows:

.. code-block:: bash

    $ pip install ccf

.. note:: The CCF Python tools package does `not` provide utilities to build and deploy CCF applications.

A step-by-step tutorial on how to use the CCF Python package is available :ref:`here <users/python_tutorial:Python Client Tutorial>`.

Uninstall
---------

To remove an installation of CCF, run:

.. code-block:: bash

    $ sudo apt remove ccf

To uninstall the CCF Python package, run:

.. code-block:: bash

    $ pip uninstall ccf