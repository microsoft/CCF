# Running CCF on a virtual machine

This folder contains two separate ways of setting up a development environment for CCF itself and apps.

1. [azure_vm](./azure_vm/README.md) provides an opinionated way of creating a Virtual Machine on Azure and install CCF for you by cloud-init.
2. `setup_vm` assumes that a bare environment is already available (VM or container) and provides Ansible scripts to setup the development environment by either cloning this repository or installing the CCF Debian package
