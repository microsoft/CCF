# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import csv
import random


COUNTRIES = ("Freedonia", "Sylvania")


def country(topic):
    """
    Return a fictional country code, consensus
    in most cases, except for Contoso.
    """
    if topic.startswith("Contoso"):
        return random.choice(COUNTRIES)
    else:
        return COUNTRIES[0]


def spread(topic):
    """
    Return a fictional spread in bps, tight triangular
    distribution in most cases, except for Fabrikam where
    the spreads are more scattered, higher, and with a longer tail.
    """
    if topic.startswith("Fabrikam"):
        if " 1Y CDS Spread" in topic:
            return random.triangular(140, 280, 180)
        elif " 3Y CDS Spread" in topic:
            return random.triangular(200, 400, 300)
        else:
            assert False
    else:
        if " 1Y CDS Spread" in topic:
            return random.triangular(140, 150)
        elif " 3Y CDS Spread" in topic:
            return random.triangular(150, 160)
        else:
            assert False


def main(polls_path, user_count):
    entries = []

    with open(polls_path, "r") as pp:
        polls = csv.DictReader(pp)
        entries = [poll for poll in polls]

    for user in range(user_count):
        with open(f"user{user}_opinions.csv", "w") as uf:
            header = ["Topic", "Opinion"]
            writer = csv.DictWriter(uf, header)
            writer.writeheader()
            for entry in entries:

                def push(opinion):
                    writer.writerow({header[0]: entry["Topic"], header[1]: opinion})

                if entry["Opinion Type"] == "string":
                    push(country(entry["Topic"]))
                elif entry["Opinion Type"] == "number":
                    push(spread(entry["Topic"]))
                else:
                    assert False


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
