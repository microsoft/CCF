Logging (Lua)
=============

CCF comes with a generic application for running Lua scripts called `lua_generic`, implemented in `lua_generic.cpp <https://github.com/microsoft/CCF/blob/master/src/apps/lua_generic/lua_generic.cpp>`_. At runtime, *lua_generic* dispatches incoming RPCs to Lua scripts stored in the table *APP_SCRIPTS*. The RPC method name is used as the key, and if a script exists at this key it is called with the RPC arguments.

The script at key ``__environment`` is special. If set, the corresponding script is invoked before any actual handler script to initialize the Lua environment.

Some global values are pre-populated in the Lua environment, to be used by both ``__environment`` and the handler scripts:

* Loggers: the functions ``LOG_TRACE``, ``LOG_DEBUG``, ``LOG_INFO``, ``LOG_FAIL``, and ``LOG_FATAL`` will call CCF's equivalent logging macros, allowing Lua apps to write to stdout.

* ``env`` table: common constants/functions should be set on this table rather than as additional global fields. This will contain a table named ``error_codes`` listing JSON RPC error codes defined by CCF (e.g., ``env.error_codes.BAD_REQUEST`` can be used rather than ``-32603``). App-specific error codes may be added to this table with values between ``APP_ERROR_START`` and ``SERVER_ERROR_END``.


RPC Handler
-----------

The following shows an implementation of the Logging application, where each RPC method handler (e.g., ``GET log/private``) is a separate entry in *APP_SCRIPTS*:

.. literalinclude:: ../../src/apps/logging/logging.lua
    :language: lua

Here, functionality shared between the handlers (e.g., ``env.jsucc()``) and app-specific error codes (e.g., ``MESSAGE_EMPTY``) are defined in the ``__environment`` script.

Interface
---------

The interface between Lua RPC handlers and the rest of CCF is simple. A fixed set of parameters is passed to a Lua RPC handler on invocation:

.. literalinclude:: ../../src/apps/logging/logging.lua
    :language: lua
    :start-after: SNIPPET_START: lua_params
    :end-before: SNIPPET_END: lua_params

* ``tables``: the set of tables the application is supposed to use for storing data. There are eight private tables (``tables.priv0`` to ``tables.priv7``) and eight public tables (``tables.priv0`` to ``tables.priv7``). The tables can map almost any Lua table/object to any Lua table/object. Internally, CCF translates Lua tables to JSON.

* ``gov_tables``: the set of governance tables the application can read. For example, ``gov_tables.membercerts`` holds the certificates of CCF members.

* ``args``: a table containing the arguments parsed from this RPC. Attempting to access any missing keys will result in an error rather than ``nil``. The valid keys are:

    * ``caller_id``: the caller's id.

    * ``method``: the method name.

    * ``params``: the RPC's ``params``, converted from JSON to a Lua table. If the JSON params were an object, this will be an object-like table with named string keys. If the JSON params were an array, this will be an array-like table with consecutive numbered keys.

The Lua value returned by an RPC handler is translated to JSON and returned to the client. To indicate an error, return a table with a key named ``error``. The value at this key will be used as the JSON error object in the response.

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

* ``end_order()``: returns the "commit version" of the table. (Probably not useful for most applications.)

