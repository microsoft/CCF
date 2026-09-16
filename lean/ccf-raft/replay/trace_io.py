# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Strict trace ingestion, including original raft_driver stdout locations."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class TraceError(ValueError):
    """A malformed, empty, or unsupported recorded trace."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TraceError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise TraceError(f"non-finite JSON number {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise TraceError(f"non-finite JSON number {value}")
    return number


def json_object(text: str, location: str) -> dict[str, Any]:
    """Decode one object without duplicate keys or non-finite numbers."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=_constant,
            parse_float=_finite_float,
        )
    except ValueError as error:
        raise TraceError(f"{location}: {error}") from error
    if not isinstance(value, dict):
        raise TraceError(f"{location}: expected a JSON object")
    return value


@dataclass(frozen=True)
class Record:
    """One unchanged record and its original input location."""

    file: str
    line: int
    raw: str
    value: dict[str, Any]

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


def parse_ndjson(lines: Iterable[str], source: str = "<input>") -> list[Record]:
    """Parse nonempty NDJSON, retaining physical line numbers."""
    records = []
    for number, line in enumerate(lines, 1):
        raw = line.rstrip("\r\n")
        records.append(
            Record(source, number, raw, json_object(raw, f"{source}:{number}"))
        )
    if not records:
        raise TraceError(f"{source}: empty trace")
    return records


def read_trace(path: Path) -> list[Record]:
    """Read strict NDJSON or verbatim captured stdout with a .stdout suffix."""
    path = path.resolve()
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            if path.suffix != ".stdout":
                return parse_ndjson(stream, str(path))
            records = []
            for number, line in enumerate(stream, 1):
                raw = line.rstrip("\r\n")
                if raw.startswith("<RaftDriver>"):
                    continue
                value = json_object(raw, f"{path}:{number}")
                if value.get("tag") == "raft_trace":
                    records.append(Record(str(path), number, raw, value))
                elif not {"h_ts", "level", "tag", "msg"} <= value.keys():
                    raise TraceError(f"{path}:{number}: unrecognized driver output")
    except UnicodeDecodeError as error:
        raise TraceError(f"{path}: invalid UTF-8: {error}") from error
    if not records or not any("msg" in record.value for record in records):
        raise TraceError(f"{path}: no Raft events; build with CCF_RAFT_TRACING=ON")
    return records
