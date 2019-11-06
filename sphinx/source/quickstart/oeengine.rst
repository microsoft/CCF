OE Engine Walkthrough
=====================

:term:`Open Enclave Engine` (OE Engine) offers detailed `deployment instructions`_, but this is a very condensed summary to get a CCF-ready VM up and running in 5 minutes. You can either execute these steps on a machine with the `Azure CLI`_ installed, or use `Azure Cloud Shell`_ (installed by the ``pre_make_vm.sh`` script).

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