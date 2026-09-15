#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Reproduce the safety-only import of the original CCF Raft proof."""

import argparse
import re
import subprocess
from pathlib import Path

REVISION = "9be0b7352"
SOURCE = "lean-tracing-demo-ccfraft/MachineGenerated"
MODULES = (
    "ModelProofs",
    "Invariant",
    "HandlerProofs",
    "UpdateTermAuthority",
    "VotedForFrame",
    "ConfigurationCoverage",
    "ReconfigurationPreservation",
)
BASE_IMPORTS = {
    "Model": "CCFRaft.Protocol.Model",
    "Properties": "CCFRaft.Protocol.Safety",
}


def namespace_for(module: str) -> str:
    """Keep witness extension methods in the namespace that defines their type."""
    owner = "Invariant" if module == "ConfigurationCoverage" else module
    return f"CCFRaft.Proofs.{owner}"


def safety_slice(module: str, text: str) -> str:
    """Keep the existing safety argument, excluding standalone retirement guarantees."""
    if module == "Invariant" and "def HasCommittedRemovalBefore" in text:
        start = text.rfind("/--", 0, text.index("def HasCommittedRemovalBefore"))
        end = text.index(
            "/-- Existentially package every consensus-safety invariant component."
        )
        text = text[:start] + text[end:]
        start = text.index(
            "/-- The complete inductive invariant includes retirement consistency."
        )
        end = text.index("\nend ", start)
        text = text[:start] + text[end:]
    elif module == "ReconfigurationPreservation":
        start = re.search(
            r"^(?:lemma|theorem) retirementInvariantFacts_refreshNode\b",
            text,
            re.MULTILINE,
        )
        if start is not None:
            end = text.index("/-! ## Reachable safety exports -/", start.start())
            text = text[: start.start()] + text[end:]
    for old, new in (
        ("SafetyInductiveInvariant", "SystemInductiveInvariant"),
        ("initialSafetyInductiveInvariant", "initialSystemInductiveInvariant"),
        ("safetyInductiveInvariantPreserved", "systemInductiveInvariantPreserved"),
        ("reachableSafetyInductiveInvariant", "reachableSystemInductiveInvariant"),
        (
            "initializeConfigurationPreservesSafetyInductiveInvariant",
            "initializeConfigurationPreservesSystemInductiveInvariant",
        ),
        (
            "dropPreservesSafetyInductiveInvariant",
            "dropPreservesSystemInductiveInvariant",
        ),
    ):
        text = re.sub(rf"\b{old}\b", new, text)
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_repository", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    sources = {
        module: safety_slice(
            module,
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(args.source_repository),
                    "show",
                    f"{REVISION}:{SOURCE}/{module}.lean",
                ],
                text=True,
            ),
        )
        for module in MODULES
    }
    imports = {
        module: re.findall(r"^import ([A-Za-z.]+)$", text, re.MULTILINE)
        for module, text in sources.items()
    }

    def dependencies(module: str) -> set[str]:
        result = set()
        for name in imports[module]:
            if name.startswith("MachineGenerated."):
                dependency = name.removeprefix("MachineGenerated.")
                if dependency not in sources:
                    raise ValueError(f"Unexpected proof dependency: {name}")
                result.add(dependency)
                result.update(dependencies(dependency))
            elif name not in BASE_IMPORTS:
                raise ValueError(f"Unexpected import: {name}")
        return result

    qualified = {
        "CCFRaft.next": "CCFRaft.Protocol.Model.next",
        "CCFRaft.system": "CCFRaft.Protocol.Model.system",
        "CCFRaft.ReconfigurationProof": "CCFRaft.Proofs.ReconfigurationPreservation",
    }
    references = set(
        re.findall(r"\bCCFRaft\.[A-Za-z0-9_]+", "\n".join(sources.values()))
    )
    for reference in references - qualified.keys():
        name = reference.removeprefix("CCFRaft.")
        owners = [
            module
            for module, text in sources.items()
            if module != "ReconfigurationPreservation"
            and re.search(rf"\b(?:theorem|lemma|def) {re.escape(name)}\b", text)
        ]
        if len(owners) != 1:
            raise ValueError(
                f"Expected one declaration owner for {reference}: {owners}"
            )
        qualified[reference] = f"{namespace_for(owners[0])}.{name}"

    generated = {}
    for module, text in sources.items():
        roots = set(
            re.findall(r"^namespace (CCFRaft(?:\.[A-Za-z]+)?)$", text, re.MULTILINE)
        )
        if len(roots) != 1:
            raise ValueError(f"Unexpected namespace roots in {module}: {roots}")
        old_namespace = roots.pop()
        namespace = namespace_for(module)
        text = re.sub(
            rf"^(namespace|end) {re.escape(old_namespace)}$",
            rf"\1 {namespace}",
            text,
            flags=re.MULTILINE,
        )
        for old, new in qualified.items():
            text = re.sub(rf"\b{re.escape(old)}\b", new, text)
        text = re.sub(r"\bReconfigurationProof\b", "ReconfigurationPreservation", text)
        text = text.replace(
            "ExecutableTransitionSystem.reachableInvariant",
            "CCFRaft.Proofs.Support.reachableInvariant",
        )
        for name in imports[module]:
            target = BASE_IMPORTS.get(
                name, name.replace("MachineGenerated.", "CCFRaft.Proofs.")
            )
            text = text.replace(f"import {name}\n", f"import {target}\n")
        text = text.replace(
            "namespace NodeStore\n",
            "namespace NodeStore\n\nopen CCFRaft.Protocol.Model.NodeStore\n",
        )
        opened = [
            "CCFRaft.Protocol",
            "CCFRaft.Protocol.Model",
            "CCFRaft.Protocol.Safety",
            "CCFRaft.Proofs.Support",
        ]
        opened += [
            namespace_for(name) for name in MODULES if name in dependencies(module)
        ]
        opened = list(dict.fromkeys(opened))
        text = text.replace(
            "set_option autoImplicit false",
            "import CCFRaft.Proofs.Support\n\n"
            + "open "
            + " ".join(opened)
            + "\n\nset_option autoImplicit false",
            1,
        )
        text = re.sub(
            r"^((?:@\[[^\n]*\]\s*)?(?:(?:private|protected) )?)theorem\b",
            r"\1lemma",
            text,
            flags=re.MULTILINE,
        )
        generated[args.destination / f"{module}.lean"] = text
    for path, text in generated.items():
        if path.exists() and path.read_text() != text:
            raise ValueError(f"Refusing to overwrite a repaired proof: {path}")
    for path, text in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"{path.name}: {len(text.splitlines())} lines from {REVISION}")


if __name__ == "__main__":
    main()
