Requirements
============

Operating Systems
-----------------

At the moment, CCF only builds and runs on Linux. It is primarily developed and tested on Ubuntu 18.04.

Hardware Requirements
---------------------

Running CCF with full security guarantees requires :term:`SGX` hardware with :term:`FLC`.

For development purposes however, it is possible to build and run CCF applications in `virtual` mode, i.e. without using SGX. The `virtual` mode does not provide any security guarantees but can be useful to quickly prototype applications or make changes to CCF itself before deploying it to a SGX-based network.

Setting Up a CCF VM
-------------------

Cloning the CCF Repository
~~~~~~~~~~~~~~~~~~~~~~~~~~

To clone the CCF repository, run the following:

.. code-block:: bash

    $ git clone --recursive https://github.com/microsoft/CCF.git

.. note:: The ``--recursive`` option is required to retrieve some third-party dependencies of CCF. It is not possible to build CCF without these dependencies.

Local Development without SGX (virtual)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning:: The `virtual` mode does not provide any security guarantees and should only be used to prototype applications.

To quickly get a container up and running in which you can build CCF, the fastest way to go is to install `Visual Studio Code`_ and install the `Remote Container`_ extension.

The CCF repository also provides a sample `devcontainer.json`_ file which will build and launch a container with all necessary CCF dependencies. It can be used to develop on non-SGX machines, as long as CCF nodes are always started in `virtual` mode.

.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers
.. _`devcontainer.json`: https://github.com/microsoft/CCF/blob/master/.devcontainer/devcontainer.json

Azure Confidential Compute
~~~~~~~~~~~~~~~~~~~~~~~~~~

:term:`Azure Confidential Compute` (ACC) offers DC-series VMs using SGX hardware, which can be deployed either through a `Marketplace App`_, or through the :term:`OpenEnclave Engine`.

.. _`Marketplace App`: https://aka.ms/ccvm

To quickly get a VM up and running, you can run the following script:

.. code-block:: bash

    $ cd CCF/getting_started/create_vm
    $ SUBSCRIPTION=$AZURE_SUBSCRIPTION_NAME ./make_vm.sh

This will create a default ``ccf`` user on the VM, authenticated by ``~/.ssh/id_rsa.pub``. If you do not have a valid SSH key under that path, you will need to either create one, or edit ``vm.json`` to select a different path.

The `SSH Remote`_ extension to `Visual Studio Code`_ makes it possible to develop your application directly on this VM.

OE Engine Walkthrough
`````````````````````

:term:`OpenEnclave Engine` (OE Engine) offers detailed `deployment instructions`_, but this is a very condensed summary to get a CCF-ready VM up and running in 5 minutes. You can either execute these steps on a machine with the `Azure CLI`_ installed, or use `Azure Cloud Shell`_.

1. Download the `oe-engine binary`_ for your platform.
2. Create a definition file as ``vm.json``:

.. code-block:: json

    {
        "properties": {
            "vmProfiles": [
            {
                "name": "ccf-test",
                "osType": "Linux",
                "vmSize": "Standard_DC2s",
                "ports": [22, 25000]
            }
            ],
            "linuxProfile": {
                "adminUsername": "ccf"
            }
        }
    }

3. Generate Azure Resource Manager deployment templates. This assumes that you are using an `SSH key`_ to authenticate, but it is also possible to use a password with adminPassword_.

.. code-block:: bash

    $ oe-engine generate --api-model vm.json --ssh-public-key ~/.ssh/id_rsa.pub --output-directory vm

4. Log in to Azure, set a default subscription and create a resource group

.. code-block:: bash

    $ az login
    $ az account set --subscription <subscription id>
    $ az group create -l eastus -n <resource group name>

5. Deploy the VM

.. code-block:: bash

    $ az group deployment create --name ccf-deploy \
                               --resource-group <resource group name> \
                               --template-file vm/azuredeploy.json \
                               --parameters @vm/azuredeploy.parameters.json

.. _`oe-engine binary`: https://github.com/Microsoft/oe-engine/releases
.. _`deployment instructions`: https://github.com/Microsoft/oe-engine/blob/master/docs/deployment.md
.. _`adminPassword`: https://github.com/Microsoft/oe-engine/blob/master/docs/examples/oe-lnx-passwd.json
.. _`Azure CLI`: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest
.. _`Azure Cloud Shell`: https://docs.microsoft.com/en-us/azure/cloud-shell/overview
.. _`SSH key`: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys
.. _`SSH Remote`: https://code.visualstudio.com/docs/remote/ssh

Installing Dependencies
-----------------------

CCF dependencies include OpenEnclave_, mbedtls_, libuv_ and libcurl_.

To quickly set up the dependencies necessary to build CCF, simply run:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./setup.sh

Once this is complete, you can proceed to :ref:`Building CCF`.

On a machine without SGX, you can instead use:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./setup_nodriver.sh

.. _OpenEnclave: https://github.com/openenclave/openenclave
.. _mbedtls: https://tls.mbed.org/
.. _libuv: https://github.com/libuv/libuv
.. _libcurl: https://curl.haxx.se/libcurl/