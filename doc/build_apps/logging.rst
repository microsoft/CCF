Logging
=======

To add your own lines to the node's output you should use the ``CCF_APP_*`` macros defined in ``ccf/ds/logger.h``:

.. code-block:: cpp

    #include "ccf/ds/logger.h"

    int x = 5;
    CCF_APP_INFO("x is currently {}", x);

Applications written in JavaScript and TypeScript can produce similar log lines using standard functions ``console.log``, ``console.info``, ``console.warn``, and ``console.error``:

.. code-block:: js

    x = 5
    console.info(`x is ${x}`)

Either approach will produce a line in the node's stdout like::

    2022-07-12T12:34:56.626262Z        0   [info ][app] ../src/my_app/my_app.cpp:42    | x is 5

These logging functions do several things:

- Variable substitution. C++ logging uses `std::format <https://en.cppreference.com/w/cpp/utility/format/format.html>`_ and compile-time checked format strings
- Declare the severity of the entry. CCF defines 5 levels (``trace``, ``debug``, ``info``, ``fail``, and ``fatal``), and production nodes will generally ignore entries below ``info``
- Prefix formatted metadata. The produced log line will include a timestamp, the name and line number where the line was produced, and an ``[app]`` tag
- Queue writes to a ringbuffer for the host to process, so diagnostic logging should not cause significant performance drops

.. note:: The app's logging entries will be interleaved (line-by-line) with the framework's logging messages. Filter for entries containing ``[app]`` to extract only application log lines.

.. note:: Since these logs are produced during execution, they will generally only appear on a single node and not every replica. They may also log information about uncommitted or re-executed transactions, as they are emitted independently of transaction commit.

C++ Formatting
--------------

CCF no longer supplies the ``fmt`` headers. C++ applications should include
``<format>`` and use ``std::format`` or ``std::format_to``. The existing C++23
requirement is unchanged, but the compiler's standard library must implement
``std::format``, including chrono formatting (for example, libstdc++ 13 or
later). C++23 range formatting and ``std::print`` are not required by CCF.

Custom formatters for application-defined types remain supported: specialise
``std::formatter<MyType>`` rather than ``fmt::formatter<MyType>``. Keep their
``parse`` functions usable in constant evaluation and their ``format``
functions ``const``. Use
``std::to_underlying(value)`` to print the numeric value of an enum without an
explicit formatter; the generic ``ccf/ds/enum_formatter.h`` header has been
removed. Types convertible to strings, filesystem paths and thread
IDs should be explicitly converted to their intended string representation.
Do not specialise ``std::formatter`` for containers of only standard-library
or fundamental types.

To format a sequence without surrounding brackets, include
``ccf/ds/join.h`` and use ``ccf::ds::join(range, separator)``. A format
specification applies to each element:

.. code-block:: cpp

    #include "ccf/ds/join.h"

    CCF_APP_INFO("Bytes: {:02x}", ccf::ds::join(bytes, " "));

The join view borrows its elements and separator; both must remain alive until
formatting completes. Iterator/sentinel pairs are also accepted as
``ccf::ds::join(begin, end, separator)``.

For genuinely runtime-supplied format strings outside the logging macros, use
``std::vformat(pattern, std::make_format_args(args...))`` with lvalue arguments.
Invalid patterns raise ``std::format_error``. The logging macros continue to
skip argument evaluation and formatting when the log level is disabled.

Optional values also need an explicit representation. CCF's claim, version,
and path diagnostics now print the contained value, or an explicit missing-value
marker, rather than the ``optional(...)`` wrapper supplied by fmt. JWT issuer
constraints retain that wrapper with JSON string quoting, whose escaping of
some control characters differs from fmt's debug-string formatting.
