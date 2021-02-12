"""Tamper Verification Tool for CCF Ledger checking"""
import argparse
import os
from ledger import Ledger


def dir_path(string):
    """Determines if the path passed is a real dir"""
    if os.path.isdir(string):
        return string
    raise NotADirectoryError(string)


def bool_string(string) -> bool:
    """Determines if the string passed is a boolean string and parses it to bool"""
    if string == 'True' or string == 'true':
        return True
    elif string == 'False' or string == 'false':
        return False
    raise ValueError(f"{string} is not of type boolean")


parser = argparse.ArgumentParser()
parser.add_argument(
    "--ledger-path", type=dir_path, required=True, help="Path to the directory containing Ledger chunks"
)

args = parser.parse_args()
ledgers_dir = args.ledger_path

ccf_ledger = Ledger(ledgers_dir)
for chunk in ccf_ledger:
    for transaction in chunk:
        transaction_public_domain = transaction.get_public_domain()
        tables = transaction_public_domain.get_tables()
        if "public:tpal.logs" in tables:
            public_tpal_table = tables["public:tpal.logs"]
            for key_value in public_tpal_table.items():
                print(f"{key_value[0]} = {key_value[1]}")
