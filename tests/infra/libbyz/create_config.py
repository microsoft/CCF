# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import os
import json


def create_private_config(public_ip, private_key):
    config_dir = "config_private"
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, public_ip), "w+") as kf:
        pk = {"privk": private_key}
        json.dump(pk, kf)


def create_config_file(f, replicas, clients):
    nodes_json = [node.node_json() for node in replicas + clients]

    configuration = {
        "num_replicas": len(replicas),
        "num_clients": len(clients),
        "max_faulty": f,
        "service_name": "generic",
        "auth_timeout": 2000000000,  # period between key changes (ms)
        "view_timeout": 5000,  # view change timeout (ms)
        "status_timeout": 100,  # status timeout for retransmissions (ms)
        "recovery_timeout": 9999250000,  # recovery timeout (ms)
        "max_requests_between_signatures": 50,  # the maximum requests before we sign a batch
        "principal_info": nodes_json,
    }

    with open("config.json", "w") as config:
        json.dump(configuration, config, indent=4)

    for replica in replicas:
        create_private_config(replica.public_ip, replica.private_key)

    for client in clients:
        create_private_config(client.public_ip, client.private_key)
