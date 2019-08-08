# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import random
from time import strftime, gmtime
import csv

data_file = "sample_data.csv"

HEADER = ["origin", "destination", "amount", "type", "src_country", "dst_country"]
KNOWN_COUNTRIES = ["US", "GB", "FR", "GR", "AU", "BR", "ZA", "JP", "IN"]
TYPES = ["PAYMENT", "TRANSFER", "CASH_OUT", "DEBIT", "CREDIT"]
rows = 10000
max_money_moved = 1000000

with open(data_file, "a") as df:
    writer = csv.writer(df)
    writer.writerow(HEADER)
    for i in range(rows):
        writer.writerow(
            [
                "C" + str(random.randint(1000, 9000)),
                "M" + str(random.randint(1000, 9000)),
                random.uniform(1, max_money_moved),
                random.choice(TYPES),
                random.choice(KNOWN_COUNTRIES),
                random.choice(KNOWN_COUNTRIES),
            ]
        )
