This folder contains scripts and utils to assist in deploying CCF nodes on C-ACI. These are not intended as general-purpose tooling, and are geared towards simplifying the manual reproduction of certain network deployments (namely, testing compatibility across different CCF versions).

These assume you have a Python env with much of the CCF infra dependencies, and the CCF Python package (`ccf_cose_sign1`) available.

Example commands as a brief tutorial:

```bash
# Create member identity to govern this service
$ keygenerator.sh --name member0 --gen-enc-key

# Create a new service with a 6.0.0 node
# Will create a new RG if none is specified
# Expects to find a member0_enc_pubk.pem alongside the member's cert
# Uses az cli, may need to install and login beforehand
$ ./ccf_aci.py --version "ccf-6.0.0" --location westeurope start --member-cert ./member0_cert.pem
...
Deployed new C-ACI instance (a CCF start node):
{
  "fqdn": "ccf-tmp-caci-20250522-121546.westeurope.azurecontainer.io",
  "ip": "20.67.127.133",
  "location": "westeurope",
  "name": "ccf-tmp-caci-20250522-121546",
  "provisioningState": "Succeeded",
  "resourceGroup": "ccf-tmp-rg-20250522-121543"
}
Spinning...

# You can terminate the above process with Ctrl+C, and the script will try to delete the C-ACI
# Alternatively, use --no-delete argument to leave it running
# Check for orphaned ccf-tmp-caci resource groups and instances in the Azure portal

# Confirm you can talk to that node from another shell
$ curl -k "https://20.67.127.133:443/node/commit"
{"transaction_id":"2.2"}

# Activate the member and open the service
# These scripts take some CLI args, but you can minimise typing by setting the CCF_NODE env var and using member0
# Remember https and port number, some tools require them
$ export CCF_NODE="https://20.67.127.133:443"

$ ./member_ack.sh
Getting state-digest for member0
Signing and submitting state-digest
Member status: "Accepted" => "Active"
Done

$ ./open_service.sh
Submitting proposal
{
  "ballotCount": 0,
  "finalVotes": {},
  "proposalId": "0be8745776e97f8cce2dd69241fe076c584dd62b19ac4f1eae8922fc5c83d216",
  "proposalState": "Accepted",
  "proposerId": "d536ab3c976f708842c11f94ac3ef7f3954d526afca79d337906d808ff1d8a69",
  "voteFailures": {}
}
Service status: "Opening" => "Open"
Done

# Start a second node, joining the first
# Generally a good idea to reuse the resource group here, to keep these instances together
$ ./ccf_aci.py --version="ccf-6.0.0" --location westeurope --resource-group ccf-tmp-rg-20250522-121543 join --target "20.67.127.133:443"
...
Deployed new C-ACI instance (a CCF join node):
{
  "fqdn": "ccf-tmp-caci-20250522-122655.westeurope.azurecontainer.io",
  "ip": "20.31.77.217",
  "location": "westeurope",
  "name": "ccf-tmp-caci-20250522-122655",
  "provisioningState": "Succeeded",
  "resourceGroup": "ccf-tmp-rg-20250522-121543"
}
Spinning...

```

If the nodes don't start, you can check the container logs in the Azure portal for a clue.
