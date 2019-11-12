# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.ccf
import functools

from loguru import logger as LOG


class TestRequirementsNotMet(Exception):
    pass


def none(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


# TODO: Parameterise this decorator once we add a test that requires a
# different number of nodes
def at_least_2_nodes(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if args[1].enforce_reqs is False:
            return func(*args, **kwargs)

        network = args[0]
        running_nodes = len(network.get_joined_nodes())
        if running_nodes < 2:
            raise TestRequirementsNotMet(
                f"Too few nodes. Only have {running_nodes}, requires 2"
            )

        return func(*args, **kwargs)

    return wrapper


def logging_app(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if args[1].enforce_reqs is False:
            return func(*args, **kwargs)

        network = args[0]
        try:
            primary, term = network.find_primary()
            with primary.user_client(format="json") as c:
                resp = c.rpc("listMethods", {})
                if "LOG_record" not in resp.result["methods"]:
                    raise TestRequirementsNotMet("Logging app not installed")
        except TestRequirementsNotMet:
            raise
        except Exception as e:
            raise TestRequirementsNotMet("Could not check if constraints were met")

        return func(*args, **kwargs)

    return wrapper


def lua_logging_app(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if args[1].enforce_reqs is False:
            return func(*args, **kwargs)

        # For now, the only way to find out whether the network is running a
        # Lua app is by looking at the package passed to the nodes at startup
        args_ = args[1]
        if args_.package is not "libluagenericenc":
            raise TestRequirementsNotMet("Lua logging app not installed")

        return func(*args, **kwargs)

    return wrapper
