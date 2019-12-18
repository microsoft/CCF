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


def ensure_reqs(check_reqs):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(network, args, *nargs, **kwargs):
            if args.enforce_reqs:
                try:
                    # This should throw TestRequirementsNotMet if any checks fail.
                    # Return code is ignored
                    check_reqs(network, args, *nargs, **kwargs)
                except TestRequirementsNotMet:
                    raise
                except Exception as e:
                    raise TestRequirementsNotMet(
                        f"Could not check if test requirements were met: {e}"
                    )

            return func(network, args, *nargs, **kwargs)

        return wrapper

    return decorator


def supports_methods(*methods):
    def check(network, args, *nargs, **kwargs):
        primary, term = network.find_primary()
        with primary.user_client() as c:
            response = c.rpc("listMethods", {})
            supported_methods = response.result["methods"]
            missing = {*methods}.difference(supported_methods)
            if missing:
                concat = ", ".join(missing)
                raise TestRequirementsNotMet(f"Missing required methods: {concat}")

    return ensure_reqs(check)


def at_least_n_nodes(n):
    def check(network, args, *nargs, **kwargs):
        running_nodes = len(network.get_joined_nodes())
        if running_nodes < n:
            raise TestRequirementsNotMet(
                f"Too few nodes. Only have {running_nodes}, requires at least {n}"
            )

    return ensure_reqs(check)


def installed_package(p):
    def check(network, args, *nargs, **kwargs):
        if args.package != p:
            raise TestRequirementsNotMet(
                f"Incorrect app. Requires '{p}', not '{args.package}'"
            )

    return ensure_reqs(check)


def lua_generic_app(func):
    return installed_package("libluagenericenc")(func)
