# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import paramiko

nodes = ["172.23.0.4"]

for node in nodes:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(node)
    sftp = client.open_sftp()
    sftp.put("setup-server.sh", "setup-server.sh")
    _, stdout, _ = client.exec_command("chmod a+x setup-server.sh && ./setup-server.sh")
    print(stdout.read().decode())
    client.close()
