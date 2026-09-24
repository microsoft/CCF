Threading
=========

CCF allows for commands to be executed on multiple threads.
This is done to increase transaction throughput while attempting to limit the effect on transaction latency.

Consistency
-----------

If all commands are executed on the primary, CCF guarantees session consistency from the perspective of a :term:`TLS` client connection.
This means that within a single client connection a client is guaranteed to read its own writes.
For example, if a client sends command (A) to the primary of a CCF service and then sends command (B), CCF guarantees that command (A) will be executed before command (B).

Implementation
--------------

Configuration
~~~~~~~~~~~~~

The ``worker_threads`` configuration option controls the number of worker threads when starting a CCF node. CCF starts one more worker thread than configured, in addition to the dispatch thread. The extra worker preserves task execution capacity now that the dispatch thread no longer executes tasks. This option defaults to ``1``, which starts two workers; a configured value of ``0`` starts one worker and logs a warning. Positive values are incremented silently.

It is strongly recommended that all CCF nodes run the same number of worker threads.

Programming Model
~~~~~~~~~~~~~~~~~

To ensure session consistency, commands that originate from the same connection are executed in order through a per-session task queue.
It is strongly advised that during the execution of a command the application does not mutate any global state outside of the key-value store.
Any inter-command communication must be performed via the key-value store, to ensure that CCF can rollback commands or change the primary as required.

Task Shutdown
~~~~~~~~~~~~~

Task cancellation prevents future execution but does not release queued actions.
Terminal shutdown additionally releases their resources, without executing application work.
The node shuts down the main ``JobBoard`` after RPC transport teardown and after all enclave worker threads have joined, while task dependencies are still alive.
Normal connection closure does not trigger this task shutdown or change the lifetime of already queued requests.

Each ``OrderedTasks`` scheduler registers weakly with its ``JobBoard`` for its lifetime.
This allows shutdown to discover paused schedulers which are absent from the ready queue, without the registry keeping idle schedulers alive.
Shutdown cancels ready, delayed, periodic and registered tasks, notifies their abandoned actions, and discards the action queues.
This breaks ownership cycles such as a session owning a scheduler whose pending action owns the session.

``shutdown()`` is terminal and idempotent.
Callers must stop task producers and join workers before invoking it; it does not interrupt an executing action.
Cleanup hooks run without queue or registry locks and must not throw.
Cleanup may submit additional work, which is immediately shut down rather than queued.
Resuming a shut-down scheduler does not reactivate it.
``on_shutdown()`` overrides can release references held by externally retained actions; action hooks must tolerate repeated notification if the same action was queued more than once.
The board destructor also performs shutdown, subject to the same lifetime and quiescence requirements.