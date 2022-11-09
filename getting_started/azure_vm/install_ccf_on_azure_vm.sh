#!/bin/bash

# !!! These are defaults and you can change these if you wish !!!
resourceGroup=rg_ccf_demo
vm_name=ccfdemo
location=westeurope
vm_size=Standard_DC16s_v3
vnetName=ccf
subnetName=nodes
vnetAddressPrefix=10.0.0.0/16
ccfAddressPrefix=10.0.0.0/24

az group create --name $resourceGroup --location $location

az network vnet create \
  --name $vnetName \
  --resource-group $resourceGroup \
  --address-prefixes $vnetAddressPrefix \
  --subnet-name $subnetName \
  --subnet-prefixes $ccfAddressPrefix

# Automatically generates a ssh key if one is not present
# https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed#generate-keys-automatically-during-deployment
az vm create \
    --resource-group $resourceGroup \
    --name $vm_name \
    --image canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:20.04.202210180 \
    --vnet-name $vnetName \
    --subnet $subnetName \
    --size $vm_size \
    --public-ip-sku Standard \
    --admin-username azureuser \
    --custom-data ccf-cloudinit.yml \
    --generate-ssh-keys \
    --output json
