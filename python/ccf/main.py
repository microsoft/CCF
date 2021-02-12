"""Tamper Verification Tool for CCF Ledger checking"""
import argparse
import os
import ledger


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger-path", type=dir_path, required=True, help="Path to the directory containing Ledger chunks"
    )

    args = parser.parse_args()
    ledgers_dir = args.ledger_path

    ccf_ledger = ledger.Ledger(ledgers_dir)
    for chunk in ccf_ledger:
        for transaction in chunk:
            transaction_public_domain = transaction.get_public_domain()
            tables = transaction_public_domain.get_tables()

            # Extracting transactions on a sample table
            # ledger.Ledger() does ledger verification implicitly
            if "public:sample.logs" in tables:
                public_tpal_table = tables["public:sample.logs"]
                for key_value in public_tpal_table.items():
                    # Knowledger of the serialization scheme is important to read the values from the table.
                    # If the table was serialized using msgpack, following code can be used to extract transaction key and value.
                    print(
                        f"{ledger.extract_msgpacked_data(key_value[0])} = {ledger.extract_msgpacked_data(key_value[1]).decode()}")
