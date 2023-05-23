#!/bin/bash
# Mount disk on client VM ready for experiments
# By default, the client uses /datadrive1/test

# Based on instructions here:
# https://learn.microsoft.com/en-us/azure/virtual-machines/linux/add-disk?tabs=ubuntu

# check disk name, script assumes sdd
lsblk -o NAME,HCTL,SIZE,MOUNTPOINT | grep -i "sd"

sudo parted /dev/sdd --script mklabel gpt mkpart xfspart xfs 0% 100%
sudo mkfs.xfs /dev/sdd1
sudo partprobe /dev/sdd1

sudo mkdir /datadrive1
sudo mount /dev/sdd1 /datadrive1

sudo chown -R azureuser /datadrive1
mkdir /datadrive1/test

sudo sh -c "echo '/dev/sdd1 /datadrive1 xfs defaults,discard   1   2' >> /etc/fstab"