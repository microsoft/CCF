import sys
import json
from rstcloth import RstCloth
from loguru import logger as LOG

if __name__ == "__main__":
    LOG.info("Generating configuration documentation")

    if len(sys.argv) <= 2:
        LOG.error(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        j = json.load(f)

    output = RstCloth()

    output.h2("Configuration Options")
    output.newline()

    for k, v in j["properties"].items():
        output.h3(f"``{k}``")
        output.newline()

        LOG.error(v)
        if v["type"] == "object":
            pass
            # for
            # output.content(v["properties"])
        else:
            desc = f'{v["description"]}'
            if "default" in v:
                default_str = v["default"]
                if v["type"] == "string":
                    default_str = f'"{default_str}"'
                desc += f" (default: {default_str})"
            desc += "."

            output.content(desc)
            output.newline()

    output.write(output_file)
