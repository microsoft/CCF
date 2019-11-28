# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import IntEnum

# Values defined in node/rpc/jsonrpc.h
class ErrorCode(IntEnum):
    # Standard JSON RPC errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # CCF-specific errors
    SERVER_ERROR_START = -32000
    TX_NOT_PRIMARY = -32001
    TX_FAILED_TO_REPLICATE = -32002
    SCRIPT_ERROR = -32003
    INSUFFICIENT_RIGHTS = -32004
    TX_PRIMARY_UNKNOWN = -32005
    RPC_NOT_SIGNED = -32006
    INVALID_CLIENT_SIGNATURE = -32007
    INVALID_CALLER_ID = -32008
    CODE_ID_NOT_FOUND = -32009
    CODE_ID_RETIRED = -32010
    RPC_NOT_FORWARDED = -32011
    QUOTE_NOT_VERIFIED = -32012
    SERVER_ERROR_END = -32099
