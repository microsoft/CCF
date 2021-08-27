Create Azure SGX VM
===================

:term:`Azure Confidential Compute` (ACC) offers SGX-enabled `DC`_-series VMs, which can be deployed like other Azure SKUs.
Note that `DC`_ SKUs can only be configured as `Gen2`_ VMs, and so only `Gen2`_ compatible VM images can be used.

.. note:: If you use `Visual Studio Code <https://code.visualstudio.com/>`_, you can install and set up the `Remote - SSH <https://code.visualstudio.com/docs/remote/ssh-tutorial>`_ extension to connect to your SGX-enabled VM.


.. _`DC`: https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series
.. _`Gen2`: https://docs.microsoft.com/en-us/azure/virtual-machines/generation-2