.. _getting_started:

Getting Started
===============

Operating Systems
-----------------

At the moment, CCF only builds and runs on Linux. It is primarily developed and
tested on Ubuntu 18.04.

Hardware
--------

Although it is possible to build and run OpenEnclave on hardware without SGX [#sgx]_ extensions,
and run CCF applications in simulation or virtual mode, running with full security guarantees
requires SGX [#sgx]_ hardware with FLC [#flc]_.

Azure Confidential Computing
----------------------------

`Azure Confidential Computing`_ offers CCF-compatible VMs, which can be deployed either through
a `Marketplace App`_, or through the `OpenEnclave Engine`_.

.. _`Azure Confidential Computing`: https://azure.microsoft.com/en-us/solutions/confidential-compute/
.. _`Marketplace App`: https://aka.ms/ccvm
.. _`OpenEnclave Engine`: https://github.com/Microsoft/oe-engine

QuickStart
``````````

To quickly get a VM up and running, you can run the following script:

.. code-block:: bash

    cd ccf/getting_started/create_vm
    SUBSCRIPTION=$AZURE_SUBSCRIPTION_NAME ./make_vm.sh

This will create a default ``ccf`` user on the VM, authenticated by ``~/.ssh/id_rsa.pub``. If you do
not have a valid SSH key under that path, you will need to either create one, or edit
``vm.json`` to select a different path.

Alternatively, you can follow the instructions in the section below.

OE Engine Walkthrough
`````````````````````

OE Engine offers detailed `deployment instructions`_, but this is a very condensed summary
to get a CCF-ready VM up and running in 5 minutes. You can either execute those steps on a
machine with the `Azure CLI`_ installed, or use `Azure Cloud Shell`_.

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

3. Generate Azure Resource Manager deployment templates. This assumes that you are using an `SSH key`_ to
authenticate, but it is also possible to use a password with adminPassword_.

.. code-block:: bash

    oe-engine generate --api-model vm.json --ssh-public-key ~/.ssh/id_rsa.pub --output-directory vm

4. Log in to Azure, set a default subscription and create a resource group

.. code-block:: bash

    az login
    az account set --subscription <subscription id>
    az group create -l eastus -n <resource group name>

5. Deploy the VM

.. code-block:: bash

    az group deployment create --name ccf-deploy \
                               --resource-group <resource group name> \
                               --template-file vm/azuredeploy.json \
                               --parameters @vm/azuredeploy.parameters.json

.. _`oe-engine binary`: https://github.com/Microsoft/oe-engine/releases
.. _`deployment instructions`: https://github.com/Microsoft/oe-engine/blob/master/docs/deployment.md
.. _`adminPassword`: https://github.com/Microsoft/oe-engine/blob/master/docs/examples/oe-lnx-passwd.json
.. _`Azure CLI`: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest
.. _`Azure Cloud Shell`: https://docs.microsoft.com/en-us/azure/cloud-shell/overview
.. _`SSH key`: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys

Dependencies
------------

QuickStart
``````````

To quickly set up the dependencies necessary to build CCF, simply run:

.. code-block:: bash

    cd ccf/getting_started/setup_vm
    ./setup.sh

Once this is complete, you can proceed to `Building CCF`_.

On a machine without SGX, you can instead use:

.. code-block:: bash

    cd ccf/getting_started/setup_vm
    ./setup_nosgx.sh

Details
```````

- OpenEnclave_
- mbedtls_
- boost_ (eEVM_ transaction engine only)
- libuv_

.. _OpenEnclave: https://github.com/Microsoft/openenclave
.. _mbedtls: https://tls.mbed.org/
.. _boost: https://www.boost.org/
.. _libuv: https://github.com/libuv/libuv
.. _eEvm: https://github.com/Microsoft/eEVM

Building CCF
-------------

.. code-block:: bash

    mkdir build
    cd build
    cmake -GNinja ..
    ninja

.. note:::

    CCF defaults to building RelWithDebInfo_.

.. _RelWithDebInfo: https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html

Build switches
--------------

The full list of build switches can be obtained by running:

.. code-block:: bash

    cmake -L ..

* **BUILD_TESTS**: Boolean. Whether to build the tests. Default to ON.
* **CLIENT_MBEDTLS_PREFIX**: Path. Prefix to mbedtls install to be used by test clients. Defaults to ``/usr/local``.
* **NO_STRICT_TLS_CIPHERSUITES**: Boolean. Whether to relax the list of accepted TLS ciphersuites. Defaults to OFF.
* **OE_PREFIX**: Path. OpenEnclave install prefix. Defaults to ``/opt/openenclave``.
* **SAN**: Boolean. Whether to build unit tests with Address and Undefined behaviour sanitizers enabled. Default to OFF.
* **VERBOSE_LOGGING**: Boolean. Level of logging detail. Default to OFF.

Tests
-----

Tests can be run through ctest:

.. code-block:: bash

    cd build
    ctest -VV

Sanitizers
``````````

To build and run the tests with the Address and Undefined behaviour sanitizers, run:

.. code-block:: bash

    cmake -GNinja .. -DSAN=ON
    ninja
    ctest -VV

On a machine without SGX, you can run the tests with:

.. code-block:: bash

    TEST_ENCLAVE=simulate ctest -VV

The build steps remain identical.

.. rubric:: Footnotes

.. [#sgx] `Intel Software Guard Extensions <https://software.intel.com/en-us/sgx>`_.
.. [#flc] `Flexible Launch Control <https://github.com/intel/linux-sgx/blob/master/psw/ae/ref_le/ref_le.md#flexible-launch-control>`_.
