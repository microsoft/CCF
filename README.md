User Documentation
------------------

Source under sphinx/, published by Azure DevOps build, accessible [here](https://ccfdoc.z6.web.core.windows.net/).

Getting Started
---------------

Under getting_started/:
 * create_vm/ contains scripts to create an ACC VM (make_vm.sh).
   You will need to export your Azure subscription name for these to work, eg: export SUBSCRIPTION=sub_name
 * setup_vm/ contains ansible playbooks that need to be run on the VM once created,
   for it to be able to build CCF.
   You can simply run ./setup.sh to execute those.
