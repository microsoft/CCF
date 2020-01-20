Environment Setup
=================

This page describes how to setup an environment to build and deploy CCF.

There are two options to deploy a CCF-ready environment:

- :ref:`Checkout CCF and its dependencies in a local container <quickstart/requirements:Local Development without SGX (virtual)>`. This is useful for quick prototyping using CCF `virtual` mode.
- :ref:`Create a SGX-enabled VM on Azure and install CCF dependencies <quickstart/requirements:Azure Confidential Compute>`.

Once this is done, you should look at how to :ref:`build CCF from source <quickstart/build:Building CCF>`.

Requirements
------------

Operating System
~~~~~~~~~~~~~~~~

At the moment, CCF only builds and runs on Linux. It is primarily developed and tested on Ubuntu 18.04.

Hardware
~~~~~~~~

Running CCF with full security guarantees requires :term:`SGX` hardware with :term:`FLC`.

For development purposes however, it is possible to build and run CCF applications in `virtual` mode, i.e. without using SGX. The `virtual` mode does not provide any security guarantees but can be useful to quickly prototype applications or make changes to CCF itself before deploying it to a SGX-based network.


Local Development without SGX (virtual)
---------------------------------------

.. warning:: The `virtual` mode does not provide any security guarantees and should only be used to prototype applications.

To quickly get a container up and running in which you can build CCF, the fastest way to go is to install Docker, `Visual Studio Code`_ and the `Remote Container`_ extension.

The CCF repository provides a sample `devcontainer.json`_ file which will build and launch a container with all necessary CCF dependencies. It can be used to develop on non-SGX machines, as long as CCF nodes are always started in `virtual` mode. See how to `checkout the CCF repository in an isolated container <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-public-git-repository-in-an-isolated-container-volume>`_.

.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers
.. _`devcontainer.json`: https://github.com/microsoft/CCF/blob/master/.devcontainer/devcontainer.json


Azure Confidential Compute
--------------------------

.. note:: These steps require an `Azure subscription <https://docs.microsoft.com/en-us/azure/billing/billing-create-subscription#create-a-subscription-in-the-azure-portal>`_.

:term:`Azure Confidential Compute` (ACC) offers DC-series VMs using SGX hardware, which can be deployed either through a `Marketplace App`_, or through the :term:`Open Enclave Engine`.

.. note:: On Windows, you can use `WSL <https://docs.microsoft.com/en-us/windows/wsl/install-win10>`_ or `Azure Cloud Shell (Bash) <https://azure.microsoft.com/en-us/features/cloud-shell/>`_ to run the following commands.

First, from your local machine, you should clone the CCF repository to get access to the scripts required to create and configure the CCF environment.

.. code-block:: bash

    $ git clone https://github.com/microsoft/CCF.git

First, you should run the ``pre_make_vm.sh`` script to install the `Azure CLI`_ and the :term:`Open Enclave Engine` (``oe-engine``) that are required to create the DC-series in Azure:

.. code-block:: bash

    $ cd CCF/getting_started/create_vm
    $ ./pre_make_vm.sh # Requires sudo privileges

Then, to quickly get a VM up and running (in the East US region), you can run the following command, specifying your personal Azure subscription as environment variable:

.. code-block:: bash

    $ SUBSCRIPTION=$AZURE_SUBSCRIPTION_NAME ./make_vm.sh [path_to_ssh_public_key]

After signing in to your Azure account, the script will create a default ``ccf`` user on the VM, authenticated by the public key specified by ``path_to_ssh_public_key`` (defaults to ``~/.ssh/id_rsa.pub``). See :ref:`quickstart/oeengine:OE Engine Walkthrough` for further details about how to deploy an ACC VM.

Then, you should ssh into your newly created vm and clone the CCF repository:

.. code-block:: bash

    $ ssh ccf@ccf-dev.eastus.cloudapp.azure.com
    $ git clone https://github.com/microsoft/CCF.git

The `SSH Remote`_ extension to `Visual Studio Code`_ makes it possible to develop your application directly on this VM.

.. _`Marketplace App`: https://aka.ms/ccvm
.. _`Azure CLI`: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
.. _`SSH Remote`: https://code.visualstudio.com/docs/remote/ssh

Installing Dependencies
-----------------------

CCF dependencies include OpenEnclave_, mbedtls_, libuv_ and libcurl_.

To quickly set up the dependencies necessary to build CCF, simply run:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./setup.sh

Once this is complete, you can proceed to :ref:`quickstart/build:Building CCF`.

On a machine without SGX, you can instead use:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./setup_nodriver.sh

.. _OpenEnclave: https://github.com/openenclave/openenclave
.. _mbedtls: https://tls.mbed.org/
.. _libuv: https://github.com/libuv/libuv
.. _libcurl: https://curl.haxx.se/libcurl/