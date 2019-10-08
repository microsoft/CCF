# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import os	
import sys	
import subprocess	

NOTICE_LINES = [	
    "Copyright (c) Microsoft Corporation.",	
    "Copyright (c) 1999 Miguel Castro, Barbara Liskov.",	
    "Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.",	
    "Licensed under the MIT license.",	
]	

PREFIXES = [	
    os.linesep.join([prefix + " " + line for line in NOTICE_LINES])	
    for prefix in ["//", "--", "#"]	
] + [	
    os.linesep.join(	
        [prefix + " " + line for line in [NOTICE_LINES[0], NOTICE_LINES[3]]]	
    )	
    for prefix in ["//", "--", "#"]	
]	

PREFIXES.append("#!/bin/bash" + os.linesep + PREFIXES[-1])	


def has_notice(path):	
    with open(path) as f:	
        text = f.read()	
        for prefix in PREFIXES:	
            if text.startswith(prefix):	
                return True	
        else:	
            return False	


def is_src(name):	
    for suffix in [".c", ".cpp", ".h", ".hpp", ".py", ".sh", ".lua"]:	
        if name.endswith(suffix):	
            return True	
    else:	
        return False	


def submodules():	
    r = subprocess.run(["git", "submodule", "status"], capture_output=True, check=True)	
    return [	
        line.strip().split(" ")[1]	
        for line in r.stdout.decode().split(os.linesep)	
        if line	
    ]	


if __name__ == "__main__":	
    missing = []	
    excluded = [] + submodules()	
    for root, dirs, files in os.walk("."):	
        for edir in excluded:	
            if edir in dirs:	
                dirs.remove(edir)	
        for name in files:	
            if name.startswith("."):	
                continue	
            if is_src(name):	
                path = os.path.join(root, name)	
                if not has_notice(path):	
                    missing.append(path)	
    for path in missing:	
        print("Copyright notice missing from {}".format(path))	
    sys.exit(len(missing))
