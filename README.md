# Confidential Consortium Framework (CCF)

The purpose of a CCF network is to run a highly secure, highly available, and high performance multi-party computation (MPC) application.

The CCF framework makes this possible by providing a key-value store replicated across a network of nodes running in Trusted Execution Environments ([TEE](https://en.wikipedia.org/wiki/Trusted_execution_environment)). They communicate with each other over secure channels based on TLS and Intel SGX remote attestations, on top of which they run a conventional Crash Fault Tolerant Replication (CFTR) protocol, Raft.

## Getting Started on Azure Confidential Computing

Under getting_started/:
 * create_vm/ contains scripts to create an ACC VM (make_vm.sh).
   This script expects a valid Azure subscription name to be set, eg: export SUBSCRIPTION=sub_name
 * setup_vm/ contains ansible playbooks that need to be run on the VM once created, for it to be able to build CCF.
   Running ./setup.sh will apply those playbooks to the VM.

## Build and Test

```bash
mkdir build
cd build
cmake -GNinja ..
ninja
```

Run the tests.

```bash
cd build
python3.7 -m venv env
source env/bin/activate
pip install -r ../tests/requirements.txt
ctest
```

## Third-party components

We rely on several open source third-party components, attributed under [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.txt).

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
