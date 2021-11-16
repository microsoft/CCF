# Adapted from https://github.com/rwestberg/lldbscripts.

# NOTE: DO NOT RENAME THIS FILE! In particular, do not replace
# the underscore with a dash. This is a requirement for import in LLDB.

# MIT License

# Copyright (c) 2019 Robin Westberg

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import lldb
import threading
import signal

class ProcessEventListener(threading.Thread):
    def __init__(self, debugger):
        super(ProcessEventListener, self).__init__()
        self._listener = debugger.GetListener()
        self._debugger = debugger
        self._interpreter = debugger.GetCommandInterpreter()
        self._handled = set()
    
    def _suppress_signals(self, process):
        # Suppress SIGILL as this is a common signal
        # in normal Open Enclave operation.
        # See https://stackoverflow.com/questions/16989988
        # for why this must happen after the process is loaded.
        signals = process.GetUnixSignals()
        signals.SetShouldStop(signal.SIGILL.value, False)

        # Load the Open Enclave lldb plugin.
        # This must happen after the process is loaded
        # because the plugin sets break points.
        self._interpreter.HandleCommand("command script import lldb_sgx_plugin", lldb.SBCommandReturnObject())

    def run(self):
        while True:
            event = lldb.SBEvent()
            if not self._listener.PeekAtNextEvent(event):
                continue                
            process = self._interpreter.GetProcess()
            if process and not process.GetUniqueID() in self._handled:
                self._suppress_signals(process)
                self._handled.add(process.GetUniqueID())

def __lldb_init_module(debugger, *rest):
    listener_thread = ProcessEventListener(debugger)
    listener_thread.start()