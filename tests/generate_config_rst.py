import sys
import json
from rstcloth import RstCloth
from loguru import logger as LOG


def print_attributes(entry):
    def stringify_output(entry, s):
        s = f'"{s}"' if entry["type"] == "string" else s
        return f"``{s}``"

    desc = ""
    if "description" in entry:
        desc += entry["description"]
    if "enum" in entry:
        desc += f' (values: {", ".join(map(lambda s: stringify_output(entry, s), entry["enum"]))})'
    if "default" in entry:
        default_str = entry["default"]
        if entry["type"] == "string":
            default_str = f'"{default_str}"'
        desc += f". Default: ``{default_str}``"
    return desc


def print_entry(output, entry, name=None):
    desc = ""
    if name is not None:
        desc += f"- ``{name}``: "
    desc += print_attributes(entry)
    output.content(f"{desc}.")
    output.newline()


# TODO:
# - network
# - command
# - required field
# - pattern

if __name__ == "__main__":
    LOG.info("Generating configuration documentation")

    if len(sys.argv) <= 2:
        LOG.error(f"Usage: {sys.argv[0]} <input_path> <output_path>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        j = json.load(f)

    output = RstCloth(line_width=1000)

    output.h2("Configuration Options")
    output.newline()

    for k, v in j["properties"].items():
        output.h3(f"``{k}``")
        output.newline()

        if "properties" in v:
            LOG.error(v)
            for a, b in v["properties"].items():
                LOG.success(b)
                if "properties" in b:
                    output.h4(f"``{a}``")
                    output.newline()
                    for x, y in b["properties"].items():
                        print_entry(output, y, name=x)
                elif "additionalProperties" in b:
                    output.h4(f"``{a}``")
                    output.newline()
                    for x, y in b["additionalProperties"]["properties"].items():
                        LOG.error(x)
                        LOG.warning(y)
                        print_entry(output, y, name=x)

                else:
                    print_entry(output, b, name=a)
        else:
            print_entry(output, v)

    output.print_content()
    output.write(output_file)
    LOG.success(f"Configuration file successfully generated at {output_file}")
