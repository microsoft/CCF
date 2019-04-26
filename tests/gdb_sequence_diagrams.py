# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
caller_to_prefix = {
    "tls::Enclave": "Enclave->>Host TLS",
    "raft::Enclave": "Enclave->>Host Raft",
    "host::TLSServer": "Host TLS->>Enclave",
    "host::RaftServer": "Host Raft->>Enclave",
}

default_prefix = "Unknown->>Unknown"

enum_maxes = None


def msg_to_string(msg):
    # In the first call, get a reference to the enum symbols
    global enum_maxes
    if enum_maxes is None:
        enum_maxes = {
            "coco::CocoMessage": gdb.lookup_symbol("coco::CocoMessage::coco_max")[
                0
            ].value(),
            "coco::RaftMessage": gdb.lookup_symbol("coco::RaftMessage::raft_max")[
                0
            ].value(),
            "coco::TlsMessage": gdb.lookup_symbol("coco::TlsMessage::tls_max")[
                0
            ].value(),
        }

    for enum_kind, max_val in enum_maxes.items():
        if msg <= max_val:
            return gdb.execute("output ({})m".format(enum_kind), to_string=True)

    return "unknown_msg"


class SequenceDiagramFileParameter(gdb.Parameter):
    def __init__(self):
        super(SequenceDiagramFileParameter, self).__init__(
            "diagramfile", gdb.COMMAND_NONE, gdb.PARAM_OPTIONAL_FILENAME
        )
        self.value = None

    def get_set_string(self):
        if self.value:
            return "Sequence diagrams will now be written to: " + self.value
        return "Sequence diagrams will not be written"

    def get_show_string(self, s):
        if s:
            return "Sequence diagrams are being written to: " + s
        return "Sequence diagrams are not currently being written"


file_param = SequenceDiagramFileParameter()


class LogWritesBreakpoint(gdb.Breakpoint):
    def stop(self):
        if file_param.value:
            # Work out who was writing with some ugly callstack string matching
            bt_lines = gdb.execute("bt 3", to_string=True).splitlines()

            prefix = default_prefix
            for line in bt_lines:
                for c, p in caller_to_prefix.items():
                    if line.find(c) != -1:
                        prefix = p
                        break
                else:
                    # If the inner loop did not break. Python!
                    continue
                break

            # Get the name of the message's enum value
            msg = gdb.selected_frame().read_var("m")
            msg_string = msg_to_string(msg)

            # Trim to unqualified name
            msg_string = msg_string[msg_string.rfind(":") + 1 :]

            rsize = gdb.selected_frame().read_var("rsize")

            # Add activations/deactivations to certain messages
            activation = (
                "+"
                if msg_string == "tls_start"
                else "-"
                if msg_string == "tls_stop"
                else None
            )
            if activation:
                marker = prefix.rfind(">") + 1
                prefix = prefix[:marker] + activation + prefix[marker:]

            with open(file_param.value, "a") as target_file:
                target_file.write("{}: {} [{}]\n".format(prefix, msg_string, rsize))

        return False


LogWritesBreakpoint("ringbuffer.h:215")
