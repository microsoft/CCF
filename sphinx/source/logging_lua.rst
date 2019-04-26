Logging (Lua)
-------------

Overview
````````

CCF comes with a generic application for running Lua scripts called *luageneric*, implemented in [CCF]/src/apps/luageneric/luageneric.cpp. At runtime, *luageneric* dispatches incoming RPCs to Lua scripts stored in the table *APP_SCRIPTS*. The initial contents of the table (i.e., at "genesis") are set by a Lua script passed to the *genesisgenerator* via the ``--app-script`` parameter. 

If the key ``__default`` exists in *APP_SCRIPTS*, then *luageneric* forwards all RPCs to the corresponding script. Otherwise, it uses an RPC's method name to lookup a handler script from *APP_SCRIPTS*. The script at key ``__environment`` is also special. If set, the corresponding script is invoked before any actual handler script to initialize the Lua environment. 

RPC Handler
```````````

The following shows an implementation of the Logging application, where each RPC method handler (e.g., ``LOG_get``) is a separate entry in *APP_SCRIPTS*:

.. literalinclude:: ../../src/apps/logging/logging.lua
    :language: lua

Here, functionality shared between the handlers (e.g., ``env.jsucc()``) is defined in the ``__environment`` script.

Interface
`````````

The interface between Lua RPC handlers and the rest of CCF is simple. A fixed set of parameters is passed to a Lua RPC handler on invocation:

.. literalinclude:: ../../src/apps/logging/logging.lua
    :language: lua
    :start-after: SNIPPET_START: lua_params
    :end-before: SNIPPET_END: lua_params

* ``tables``: the set of tables the application is supposed to use for storing data. There are eight private tables (``tables.priv0`` to ``tables.priv7``) and eight public tables (``tables.priv0`` to ``tables.priv7``). The tables can map almost any Lua table/object to any Lua table/object. Internally, CCF translates Lua tables to JSON.

* ``gov_tables``: the set of governance tables the application can read. For example, ``gov_tables.membercerts`` holds the certificates of CCF members.

* ``caller_id``: the caller's id.

* ``msg_id``: the RPC's id.

* ``params``: the RPC's parameters indexed by name. All JSON is translated to Lua tables.

The Lua table returned by an RPC handler is translated to JSON and returned to the client.

Accessing Tables
~~~~~~~~~~~~~~~~

The tables passed to a Lua handler in ``tables`` and ``gov_tables`` can be accessed through a set of methods. These are:

* ``get(key)``: returns the value stored at ``key``. If no such entry exists, returns nil. Example: 

.. code-block:: lua

    tables.priv0:get("a")

* ``put(key, value)``: puts a key-value pair into the table.

* ``foreach(func)``: calls ``func(key, value)`` for each key-value pair stored in the table. Can for example be used to count the number of entries in a table as follows:

.. code-block:: lua

    n = 0
    tables.priv0:foreach(function f(k,v) n = n + 1 end)

* ``start_order()``: returns the "start version" of the table. (Probably not useful for most applications.)

* ``end_order()``: returns the "commit versio" of the table. (Probably not useful for most applications.)


Running
```````

First, the Lua application is written to the initial state using the *genesisgenerator*:

.. code-block:: bash

    ./genesisgenerator --app-script myapp.lua [args]

Next, CCF is started with *luageneric* as enclave file:

.. code-block:: bash

    ./cchost --enclave-file libluageneric.signed.so [args]



