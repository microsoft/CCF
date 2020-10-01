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

These dependencies can be conveniently installed using the ``ansible`` playbooks in the CCF repository:

.. code-block:: bash

    $ git clone https://github.com/microsoft/CCF.git
    $ cd CCF/getting_started/setup_vm
    $ ./run.sh driver.yml # Only on SGX-enabled hardware
    $ ./run.sh app-run.yml

Install
-------

CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases/latest>`_.

Confidential Consortium Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The CCF debian package (``ccf_<version>_amd64.deb``) contains the libraries and utilities to start a CCF service and build CCF applications. CCF can be installed as follows:

.. code-block:: bash

    $ export CCF_VERSION=0.14.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_VERSION}_amd64.deb
    $ sudo apt install ./ccf_${CCF_VERSION}_amd64.deb

Assuming that CCF was installed under ``/opt``, the following command can be run to verify that CCF was installed successfully:

.. code-block:: bash

    $ /opt/ccf-${CCF_VERSION}/bin/cchost --version
    CCF host: ccf-<version>

# TODO: Also include sufficient Python to start a test network. Also `tree` the install and explain the different things in it.

Python Package
~~~~~~~~~~~~~~

The CCF Python tools package can be used to interact with an existing running service and provides utilities to:

- Issue HTTP requests over TLS to CCF applications
- Build custom governance proposals and votes
- Parse and verify the integrity of a CCF ledger

The latest version of the CCF Python tools package can be installed as follows:

.. code-block:: bash

    $ pip install ccf


.. note:: The CCF Python tools package does `not` provide utilities to build and deploy CCF applications.

# TODO: Link to tutorial

Uninstall
---------

To remove an installation of CCF, run:

.. code-block:: bash

    $ sudo apt remove ccf

To uninstall the CCF Python package, run:

.. code-block:: bash

    $ pip uninstall ccf


Container
---------
# TODO: Move this, this is only for deploying existing applications??

The ``ccfciteam/ccf-app-run`` container can be run to setup an environment containing the ``cchost`` binary (as per the `latest release of CCF <https://github.com/microsoft/CCF/releases/latest>`_) and the associated dependencies:

.. code-block:: bash

    $ docker run -ti ccfciteam/ccf-app-run
    root@6fc0cfa4b9e1:/# cchost --version
    CCF host: ccf-<version>

CCF applications can be mounted to the container and deployed with the ``cchost`` binary.

# TODO: Link to building and running app
