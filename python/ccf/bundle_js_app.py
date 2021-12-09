# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import glob
import json
import os
import shutil
import tempfile


def read_modules(modules_path):
    modules = []
    for path in glob.glob(f"{modules_path}/**/*", recursive=True):
        if not os.path.isfile(path):
            continue
        rel_module_name = os.path.relpath(path, modules_path)
        rel_module_name = rel_module_name.replace("\\", "/")  # Windows support
        with open(path, encoding="utf-8") as f:
            js = f.read()
            modules.append({"name": rel_module_name, "module": js})
    return modules


def create_bundle(bundle_path):
    # read modules
    if os.path.isfile(bundle_path):
        tmp_dir = tempfile.TemporaryDirectory(prefix="ccf")
        shutil.unpack_archive(bundle_path, tmp_dir.name)
        bundle_path = tmp_dir.name
    modules_path = os.path.join(bundle_path, "src")
    modules = read_modules(modules_path)

    # read metadata
    metadata_path = os.path.join(bundle_path, "app.json")
    with open(metadata_path, encoding="utf-8") as f:
        metadata = json.load(f)

    # sanity checks
    module_paths = set(module["name"] for module in modules)
    for url, methods in metadata["endpoints"].items():
        for method, endpoint in methods.items():
            module_path = endpoint["js_module"]
            if module_path not in module_paths:
                raise ValueError(
                    f"{method} {url}: module '{module_path}' not found in bundle"
                )
    return {"metadata": metadata, "modules": modules}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_path", type=str, help="Path to CCF JS app directory")
    args = parser.parse_args()
    print(json.dumps(create_bundle(args.bundle_path), indent=2))
