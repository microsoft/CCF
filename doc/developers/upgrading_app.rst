Upgrade Your Application
========================

As CCF is still in pre-release, it is possible that new versions of the framework will break existing applications. As such, these may require updates to compile and run successfully when upgrading CCF.

The sample `logging application <https://github.com/microsoft/CCF/tree/master/src/apps/logging>`_ is currently the reference application that developers should look at when building and upgrading their application.

.. note::

    GitHub offers a convenient way to compare two releases by the ``Compare`` drop-down button next to each release. It is also possible to use the following URL: ``https://github.com/microsoft/CCF/compare/<old_release_tag>..<new_release_tag>``, e.g. `<https://github.com/microsoft/CCF/compare/ccf-0.14.0..ccf-0.13.4>`_. For example, the changes to the ``logging.cpp`` file should display the changes required to upgrade your C++ application, including new features.

.. warning::

    It is also possible that the governance Lua script also requires updating. You can compare your governance script with the `latest governance script samples available in GitHub <https://github.com/microsoft/CCF/tree/master/src/runtime_config>`_.