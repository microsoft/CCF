Start Here
==========

Container
---------

The quickest way to get started building CCF applications is to use the :ref:`developers/build_app:Build Container`.

.. code-block:: bash

    sudo docker run -it ccfciteam/ccf-app-ci:latest

That contains a release of CCF along with a complete build toolchain, and startup scripts. It can be run
on hardware that does not support SGX, in which case you will want to use the virtual binaries, or build in `virtual mode`.

.. note::

    `virtual` mode provides no security guarantee. It is only useful for development and prototyping.

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample `devcontainer.json`_ config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-public-git-repository-in-an-isolated-container-volume>`_.

.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers
.. _`devcontainer.json`: https://github.com/microsoft/CCF/blob/master/.devcontainer/devcontainer.json

If your hardware does support SGX, and has the appropriate driver installed and loaded, then you will only need to expose
the device to the container by passing ``--device /dev/sgx:/dev/sgx`` when you start it.

SGX-enabled VM
---------------

The install directory contains (under ``getting_started/``) the Azure and Ansible scripts required to create and set up
an SGX-enabled dev VM in Azure, with all necessary dependencies to build CCF itself or CCF applications.

Creation
~~~~~~~~

These steps require an `Azure subscription <https://docs.microsoft.com/en-us/azure/billing/billing-create-subscription#create-a-subscription-in-the-azure-portal>`_.

:term:`Azure Confidential Compute` (ACC) offers DC-series VMs using SGX hardware, which can be deployed either through a `Marketplace App`_, or via the following command line instructions.
On Windows, you can use `WSL <https://docs.microsoft.com/en-us/windows/wsl/install-win10>`_ or `Azure Cloud Shell (Bash) <https://azure.microsoft.com/en-us/features/cloud-shell/>`_ to run these.

First clone the `CCF repository <https://github.com/microsoft/CCF>`_ or download a release tarball `here <https://github.com/microsoft/CCF/releases>`_.
Run the ``pre_make_vm.sh`` script to install the `Azure CLI`_ and the :term:`Open Enclave Engine` (``oe-engine``) that are required to create the DC-series in Azure:

.. code-block:: bash

    $ cd CCF/getting_started/create_vm
    $ ./pre_make_vm.sh # Requires sudo privileges

Then, to get a VM up and running in the East US region, you can run the following command:

.. code-block:: bash

    $ ./make_vm.sh $AZURE_SUBSCRIPTION_NAME [path_to_ssh_public_key]

After signing in to your Azure account, the script will create a default ``ccf`` user on the VM, authenticated by the public key specified by ``path_to_ssh_public_key`` (defaults to ``~/.ssh/id_rsa.pub``).

.. _`Marketplace App`: https://aka.ms/ccvm
.. _`Azure CLI`: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

Setup
~~~~~

CCF dependencies include OpenEnclave_, mbedtls_, libuv_ and libcurl_.

To quickly set up the dependencies necessary to build CCF, simply run:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./run.sh driver.yml ccf-dev.yml

Once this is complete, you can proceed to :ref:`quickstart/build:Building CCF from Source`.

On a machine without SGX, you can instead run:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./run.sh ccf-dev.yml

.. _OpenEnclave: https://github.com/openenclave/openenclave
.. _mbedtls: https://tls.mbed.org/
.. _libuv: https://github.com/libuv/libuv
.. _libcurl: https://curl.haxx.se/libcurl/

Next Steps
----------

Once your setup is complete, you may want to get familiar with some of CCF's :ref:`Concepts <concepts:Concepts>`. You will then be able to:

1. :ref:`Create a consortium and agree on the constitution <members/index:Governance>`
2. :ref:`Develop a CCF application, based on the example logging application <developers/example:Example Application>`
3. :ref:`Start a new CCF network to deploy the application <operators/start_network:Starting a New Network>`
4. :ref:`Let the consortium configure and open the network to users <members/open_network:Opening a Network>`
5. :ref:`Have users issue business transactions to the application <users/index:Using Apps>`

Requirements
------------

At the moment, CCF only builds and runs on Linux. It is primarily developed and tested on Ubuntu 18.04.
Running CCF with full security guarantees requires :term:`SGX` hardware with :term:`FLC`.

Releases
--------

CCF releases (``ccf.tar.gz``) are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_.
Once downloaded, the extracted install directory can be copied to a long-lived path, e.g. ``/opt/ccf-install``.

To setup a CI for your CCF application, you may want to use the :ref:`developers/build_app:Build Container`. If you are running
CCF nodes in containers, the :ref:`operators/container:Runtime Container` is a good place to start.
