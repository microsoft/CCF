#!/bin/bash

# !!! Update these before running this script !!!
resourceGroup=rg_ccfdemo
vm_name=ccfdemo
vm_dns=ccfdemo-vm-sample
# !!!

# These are defaults
location=westeurope
vm_size=Standard_DC1s_v2
vnetName=ccf
subnetName=nodes
vnetAddressPrefix=10.0.0.0/16
nodeAddressPrefix=10.0.0.0/24

az group create --name $resourceGroup --location $location

az network vnet create \
  --name $vnetName \
  --resource-group $resourceGroup \
  --address-prefixes $vnetAddressPrefix \
  --subnet-name $subnetName \
  --subnet-prefixes $nodeAddressPrefix

# Automatically generates a ssh key if one is not present
# https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed#generate-keys-automatically-during-deployment
az vm create \
    --resource-group $resourceGroup \
    --name $vm_name \
    --image canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:20.04.202210180 \
    --vnet-name $vnetName \
    --subnet $subnetName \
    --generate-ssh-keys \
    --size $vm_size \
    --public-ip-sku Standard \
    --public-ip-address-dns-name $vm_dns \
    --assign-identity \
    --admin-username azureuser \
    --custom-data ccf-cloudinit.yml \
    --output json
