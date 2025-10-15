CCF Development Setup
=====================

From version 6.0.0, CCF is primarily built for and tested on Azure Linux 3. We recommend starting from the latest `azure-linux-3` image in your container or VM.

Environment Setup
-----------------

First checkout the CCF repository or :doc:`install the latest CCF release </build_apps/install_bin>`.

Then, to set up the dependencies necessary to build CCF itself and its tests, run:

.. code-block:: bash

    cd <ccf_path>/scripts
    ./setup-ci.sh
    ./scripts/setup-dev.sh
    
Once this is complete, you can proceed to :doc:`/build_apps/build_app`.

Visual Studio Code Setup
~~~~~~~~~~~~~~~~~~~~~~~~

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample :ccf_repo:`devcontainer.json <.devcontainer/devcontainer.json>` config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-git-repository-or-github-pr-in-an-isolated-container-volume>`_.


.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers

Developing for Azure Linux OS
-----------------------------

Developing in GitHub Codespaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CCF devcontainer setup works just fine with codespaces. It's recommended to pre-configure for 16-cores one.

Tweaks for codespaces:

* In order to run lldb in a container, run this command first "settings set target.disable-aslr false"

How to install docker
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    sudo tdnf install moby-engine moby-cli ca-certificates -y  
    sudo systemctl enable docker.service  
    sudo systemctl daemon-reload  
    sudo systemctl start docker.service

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
