import json
import os
import sys

# Example usage:
# $ cd path/to/your/app/src
# $ python -m ccf.bundle_js_modules **/* > ../modules.json
# $ jq -n '{metadata: input, modules: input}' ../app.json ../modules.json > bundle.json
# $ build_proposal.sh --action set_js_app -j bundle @bundle.json

if __name__ == "__main__":
    modules = list({"name": path, "module": open(path).read()} for path in sys.argv[1:] if os.path.isfile(path))
    print(json.dumps(modules, indent=2))