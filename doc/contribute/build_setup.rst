CCF Development Setup
=====================

Environment Setup
-----------------

First, on your development VM, checkout the CCF repository or :doc:`install the latest CCF release </build_apps/install_bin>`.

Then, to quickly set up the dependencies necessary to build CCF itself and CCF applications, simply run:

.. tab:: SNP

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm
        $ ./run.sh ccf-dev.yml

.. tab:: Virtual

    .. warning:: The `virtual` version of CCF can also be run on hardware that does not support SEV-SNP. Virtual mode does not provide any security guarantees and should be used for development purposes only.

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm
        $ ./run.sh ccf-dev.yml

Once this is complete, you can proceed to :doc:`/build_apps/build_app`.

Build Container
---------------

The quickest way to get started building CCF applications is to use the CCF build container. It contains all the dependencies needed to build and test CCF itself as well as CCF applications.

.. code-block:: bash

    $ export VERSION="4.0.0"
    $ export PLATFORM="snp" # snp or virtual
    $ docker pull mcr.microsoft.com/ccf/app/dev:$VERSION-$PLATFORM

The container contains the latest release of CCF along with a complete build toolchain, and startup scripts.

.. note::

    - `virtual` mode provides no security guarantee. It is only useful for development and prototyping.

Visual Studio Code Setup
~~~~~~~~~~~~~~~~~~~~~~~~

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample :ccf_repo:`devcontainer.json <.devcontainer/devcontainer.json>` config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-git-repository-or-github-pr-in-an-isolated-container-volume>`_.


.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers

Develor for Azure Linux OS
--------------------------

Setting up Azure Linux VM
~~~~~~~~~~~~~~~~~~~~~~~~~

See the official Azure Linux documentation for developers for details: `Azure Linux VMs in Azure | Mariner OS <https://eng.ms/docs/products/azure-linux/gettingstarted/azurevm/azurevm>`_.

In short, there's no possibility to choose an image in UI, so the CLI steps required to get an Azure Linux based VM in Microsoft Azure are

.. code-block:: bash

    az group create --name [GROUP_NAME] --location eastus2
    az vm create --name [VM-NAME] --resource-group [GROUP_NAME] --image MicrosoftCBLMariner:azure-linux-3:azure-linux-3:latest --admin-username [USERNAME] --ssh-key-values C:\Users\[USERNAME\.ssh\[KEY].pub --os-disk-size-gb 512

Afterwards, go to your VM and select a proper RAM and CPU profile. I you don't know which one you want, select `Standard D16s v3` (64 RAM and 16 CPU cores).

Then select a proper network security group and rules to use your VM. Refer to other VMs you have and reuse the same group if you have doubts.

How to install docker
~~~~~~~~~~~~~~~~~~~~~

Currently the only sensible way we've found is downloading binaries: https://docs.docker.com/engine/install/binaries/#install-daemon-and-client-binaries-on-linux.

.. code-block:: bash

    wget https://download.docker.com/linux/static/stable/x86_64/docker-28.0.1.tgz
    tar xzvf docker-28.0.1.tgz
    sudo cp docker/* /usr/bin/
    sudo dockerd &
    sudo docker run hello-world

How do I install an EXTENDED package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are 2 lists of packages in the official Azure Linux repo - `SPECS <https://github.com/microsoft/azurelinux/tree/3.0/SPECS>`_
and `SPECS-EXTENDED <https://github.com/microsoft/azurelinux/tree/3.0/SPECS-EXTENDED>`_.

The latter are hosted on `packages.microsoft.com <https://packages.microsoft.com/azurelinux/3.0/prod/extended/x86_64/>`_, but to consume them you'll need to manually add the repo. One way to do this is to put the .repo file directly into ``/etc/yum.repos.d``:

.. code-block:: bash

    sudo wget https://packages.microsoft.com/azurelinux/3.0/prod/extended/x86_64/config.repo -O /etc/yum.repos.d/azurelinux-official-extended.repo

Where is perf?
~~~~~~~~~~~~~~

In `kernel-tools <https://github.com/microsoft/azurelinux/discussions/6476>`_. If anyone works out how to get ``tdnf repoquery`` to say this, please add it here.

How do I find more information about Azure Linux?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Try searching for "Mariner". This was Azure Linux's previous name, a lot of useful support discussions happened under that name, and it's far easier to search for.
