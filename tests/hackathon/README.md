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