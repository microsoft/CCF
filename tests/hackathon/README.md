# PoC sample application for flagging and revealing fraudulent transactions

To run this demo and have the results visualized using ELK you will need to follow the below instructions

## Filebeat

* ** https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html
* ** replace /etc/filebeat/filebeat.yml with the yml config file located in the tests/hackathon directory
* ** place the certificate file (logstash-beats.crt) in the correct location, indicated in the flatbeat.yml file
* ** `$ sudo service filebeat restart`
* ** `$ sudo service filebeat status`

## ELK docker container 

* ** `$ sudo sysctl -w vm.max_map_count=262144`
* ** https://elk-docker.readthedocs.io/#installation (docker pull and docker run)
* ** add the below line in /etc/hosts "127.17.0.2 elk" to expose the docker host

## Forward port via VSCode

* ** `Forward port from active host` for port 5601

## Run the demo

From the build directory run `../tests/hackathon/run_demo.sh <path to dataset file>`. This will run the loader.py script which load
the dataset provided, and it will launch the poll.py script which polls the service for flagged transactions, reveals and retrieved 
the revealed transactions. 

The logs that will be pushed to ELK will be in the build directory and are transactions.log for the transactions and revealed.log
for the revealed transactions.

## Kibana Dashboard

You can find the Kibana dashboard that is used for this demo in the `tests/hackathon/Demo_Dashboard_v0.1.ndjson`file. 
You just need to import that into Kibana.

## What is this app/demo doing?

There are banks and regulators. Banks issue transactions that can not be leaked outside of CCF. Regulators register algorithms that
return true or false but do not reveal any transactions. The algorithms run on each transaction that the banks issue.

If a transaction is flagged (i.e. an algorithm returns true), then the flagged transactions table gets populated. In that table the
key will be the `tx_id` and it will map to `[regulator id, revealed, timestamp, regulator name]` where `revealed` is a boolean 
indicating  if the transaction has been revealed or not. A flagged transaction does not mean that it's details are visible to regulators 
(hence the `revealed` boolean). 

The bank that issued the transaction can then go and reveal it by setting the `revealed` boolean to true. The regulator can then see
all the details related to it (src_country, dst_country, amt, etc).