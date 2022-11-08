# Creating a Virtual Machine in Azure to run CCF

This guide is here to give you the bare minimum to get started with CCF. It will walk you through the steps to create a virtual machine in Azure and install CCF on it.

## Prerequisites

You must run this from a bash terminal that you have already logged in to Azure with. If you have not done this, please follow the instructions [here](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest).

## Create a Virtual Machine

Edit the `./infra/azure.sh` script and set the following variables to be unique to you (it is important to change the DNS name):

```bash
resourceGroup=rg_ccf
vm_name=ccf
vm_dns=ccf-vm-sample
```

Then run the script:

```bash
./install_ccf_on_azure_vm.sh
```
