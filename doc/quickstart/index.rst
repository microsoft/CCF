Start Here
==========

CCF releases (``ccf.tar.gz``) are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_. Once downloaded, the extracted install directory can be copied to a long-lived path, e.g. ``/opt/ccf-install``.

The install directory contains (under ``getting_started/``) the Azure and Ansible scripts required to setup the CCF environment. See :ref:`how to setup the CCF environment here <quickstart/requirements:Azure Confidential Compute>`.

.. note::

    Note that for rapid prototyping, it is possible to run CCF in a non-SGX-enabled environment, using CCF's `virtual` mode (`warning: no security guarantee provided`).

.. note::

    When upgrading a pre-1.0 CCF, it is possible that your application will require some changes to compile. See :ref:`quickstart/upgrading_app:Upgrading Your Application` for more details.

Once your setup is complete, you should also get familiar with some of CCF's :ref:`Concepts <concepts:Concepts>`. You will then be able to:

1. :ref:`Create a consortium and agree on the constitution <members/index:Governance>`
2. :ref:`Develop a CCF application, based on the example logging application <developers/example:Example Application>`
3. :ref:`Start a new CCF network to deploy the application <operators/start_network:Starting a New Network>`
4. :ref:`Let the consortium configure and open the network to users <members/open_network:Opening a Network>`
5. :ref:`Have users issue business transactions to the application <users/index:Using Apps>`

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    requirements
    oeengine
    build
    upgrading_app