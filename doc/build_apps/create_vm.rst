Create Azure SGX VM
===================

.. note:: These steps require an `Azure subscription <https://docs.microsoft.com/en-us/azure/billing/billing-create-subscription#create-a-subscription-in-the-azure-portal>`_.

Creation
--------

The install directory contains (under ``getting_started/``) the Azure and Ansible scripts required to create and setup an SGX-enabled development VM in Azure, with all necessary dependencies to build CCF itself and CCF applications.

.. note:: If you use `Visual Studio Code <https://code.visualstudio.com/>`_, you can install and set up the `Remote - SSH <https://code.visualstudio.com/docs/remote/ssh-tutorial>`_ extension to connect to your SGX-enabled VM.

:term:`Azure Confidential Compute` (ACC) offers DC-series VMs using SGX hardware, which can be deployed either through a `Marketplace App`_, or via the following command line instructions.
On Windows, you can use `WSL <https://docs.microsoft.com/en-us/windows/wsl/install-win10>`_ or `Azure Cloud Shell (Bash) <https://azure.microsoft.com/en-us/features/cloud-shell/>`_ to run these.

First clone the `CCF repository <https://github.com/microsoft/CCF>`_ or download the latest release of CCF `here <https://github.com/microsoft/CCF/releases>`_.
Run the ``pre_make_vm.sh`` script to install the `Azure CLI`_ and the :term:`Open Enclave Engine` (``oe-engine``) that are required to create the DC-series in Azure:

.. code-block:: bash

    $ cd <ccf_path>/getting_started/create_vm
    $ ./pre_make_vm.sh # Requires sudo privileges

Then, to get a VM up and running in the UK South region, run the following command:

.. code-block:: bash

    $ ./make_vm.sh $AZURE_SUBSCRIPTION_NAME [path_to_ssh_public_key]

After signing in to your Azure account, the script will create a default ``ccf`` user on the ``ccf-dev-vm`` VM (part of ``ccf-dev-rg`` resource group), authenticated by the public key specified by ``path_to_ssh_public_key`` (defaults to ``~/.ssh/id_rsa.pub``).

Deletion
--------

.. warning::
    - Make sure that all your changes are committed and pushed to GitHub before destroying the VM.
    - The destroy script will destroy all resources in the ``ccf-dev-rg`` resource group previously created by the ``make_vm.sh`` script.

Once the development on the Azure SGX VM is complete, the VM can be destroyed as follows:

.. code-block:: bash

    $ cd CCF/getting_started/create_vm
    $ ./destroy_vm.sh $AZURE_SUBSCRIPTION_NAME

.. _`Marketplace App`: https://aka.ms/ccvm
.. _`Azure CLI`: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli