# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import infra.proc
import collections

from loguru import logger as LOG

COMMIT_COUNT_CUTTOF = 20


class TxRates:
    def __init__(self, primary):
        self.get_histogram = False
        self.primary = primary
        self.same_commit_count = 0
        self.data = {}
        self.commit = 0

        with open("getTxHist.json", "w") as gtxrf:
            gtxrf.write('{"id":1,"jsonrpc":"2.0","method":"getTxHist","params":{}}\n')
        with open("getTxRates.json", "w") as gtxrf:
            gtxrf.write('{"id":1,"jsonrpc":"2.0","method":"getTxRates","params":{}}\n')
        with open("getCommit.json", "w") as gcf:
            gcf.write('{"id":1,"jsonrpc":"2.0","method":"getCommit","params":{}}\n')

    def process_next(self):
        rv = infra.proc.ccall(
            "./client",
            "--host={}".format(self.primary.host),
            "--port={}".format(self.primary.tls_port),
            "--ca=networkcert.pem",
            "userrpc",
            "--cert=user1_cert.pem",
            "--pk=user1_privk.pem",
            "--req=getCommit.json",
            log_output=False,
        )
        print(rv.stdout.decode())
        result = rv.stdout.decode().split("\n")[1]
        result = json.loads(result)
        next_commit = result["result"]["commit"]
        if self.commit == next_commit:
            self.same_commit_count += 1
        else:
            self.same_commit_count = 0

        self.commit = next_commit

        if self.same_commit_count > COMMIT_COUNT_CUTTOF:
            self._get_hist()
            return False
        return True

    def print_results(self):
        print(json.dumps(self.data, indent=4))

    def save_results(self):
        with open("tx_rates.txt", "w") as file:
            for key in sorted(self.data.keys()):
                file.write(key + " : " + str(self.data[key]))
                file.write("\n")

    def _get_hist(self):
        rv = infra.proc.ccall(
            "./client",
            "--host={}".format(self.primary.host),
            "--port={}".format(self.primary.tls_port),
            "--ca=networkcert.pem",
            "userrpc",
            "--cert=user1_cert.pem",
            "--pk=user1_privk.pem",
            "--req=getTxRates.json",
            log_output=False,
        )

        result = rv.stdout.decode().split("\n")[1]
        result = json.loads(result)
        result = result["result"]["tx_rates"]
        max = 0
        for key in result:
            if result[key]["rate"] > max:
                max = result[key]["rate"]
        print(json.dumps(result, indent=4))
        print("MAX")
        print(max)

        rv = infra.proc.ccall(
            "./client",
            "--host={}".format(self.primary.host),
            "--port={}".format(self.primary.tls_port),
            "--ca=networkcert.pem",
            "userrpc",
            "--cert=user1_cert.pem",
            "--pk=user1_privk.pem",
            "--req=getTxHist.json",
            log_output=False,
        )

        result = rv.stdout.decode().split("\n")[1]
        result = json.loads(result)
        histogram = result["result"]["tx_hist"]["histogram"]
        LOG.info("Filtering histogram results...")
        hist_data = {}

        for key in histogram:
            if histogram[key] > 0:
                self.data[key] = histogram[key]
        self.data["low"] = result["result"]["tx_hist"]["low"]
        self.data["high"] = result["result"]["tx_hist"]["high"]
        self.data["underflow"] = result["result"]["tx_hist"]["underflow"]
        self.data["overflow"] = result["result"]["tx_hist"]["overflow"]
