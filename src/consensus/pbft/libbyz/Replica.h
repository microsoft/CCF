// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Big_req_table.h"
#include "Certificate.h"
#include "Digest.h"
#include "LedgerReplay.h"
#include "LedgerWriter.h"
#include "Log.h"
#include "New_principal.h"
#include "Node.h"
#include "Partition.h"
#include "Prepared_cert.h"
#include "Req_queue.h"
#include "Stable_estimator.h"
#include "State.h"
#include "View_info.h"
#include "libbyz.h"
#include "receive_message_base.h"
#include "types.h"

#ifdef ENFORCE_EXACTLY_ONCE
#  include "Rep_info_exactly_once.h"
#else
#  include "Rep_info.h"
#endif

class Request;
class Reply;
class Pre_prepare;
class Prepare;
class Commit;
class Checkpoint;
class Status;
class View_change;
class New_view;
class New_key;
class Fetch;
class Data;
class Meta_data;
class Meta_data_d;
class Reply;
class Query_stable;
class Reply_stable;

#define DEBUG_SLOW

#define ALIGNMENT_BYTES 2
static constexpr int SMALL_REPLY_THRESHOLD = 50;

class Replica : public Node, public IMessageReceiveBase
{
public:
  Replica(
    const NodeInfo& node_info,
    char* mem,
    size_t nbytes,
    INetwork* network,
    std::unique_ptr<consensus::LedgerEnclave> ledger = nullptr);
  // Requires: "mem" is vm page aligned and nbytes is a multiple of the
  // vm page size.
  // Effects: Create a new server replica using the information in
  // node_info. The replica's state is set to the
  // "nbytes" of memory starting at "mem".

  virtual ~Replica();
  // Effects: Kill server replica and deallocate associated storage.
  void recv();
  // Effects: Loops receiving messages and calling the appropriate
  // handlers.

  // Methods to register service specific functions. The expected
  // specifications for the functions are defined below.
  void register_exec(ExecCommand e);
  // Effects: Registers "e" as the exec_command function.

  void register_nondet_choices(void (*n)(Seqno, Byz_buffer*), int max_len);
  // Effects: Registers "n" as the non_det_choices function.

  void compute_non_det(Seqno n, char* b, int* b_len);
  // Requires: "b" points to "*b_len" bytes.
  // Effects: Computes non-deterministic choices for sequence number
  // "n", places them in the array pointed to by "b" and returns their
  // size in "*b_len".

  int max_nd_bytes() const;
  // Effects: Returns the maximum length in bytes of the choices
  // computed by compute_non_det

  int used_state_bytes() const;
  // Effects: Returns the number of bytes used up to store protocol
  // information.

  void modify(void* mem, int size);
  // Effects: Informs the system that the memory region that starts at
  // "mem" and has length "size" bytes is about to be modified.

  void modify_index(int bindex);
  // Effects: Informs the system that the memory page with index
  // "bindex" is about to be modified.

  void process_new_view(Seqno min, Digest d, Seqno max, Seqno ms);
  // Effects: Update replica's state to reflect a new-view: "min" is
  // the sequence number of the checkpoint propagated by new-view
  // message; "d" is its digest; "max" is the maximum sequence number
  // of a propagated request +1; and "ms" is the maximum sequence
  // number known to be stable.

  void write_view_change_to_ledger();

  void send_view_change();
  // Effects: Send view-change message.

  void send_status(bool send_now = false);
  // Effects: Sends a status message.

  void register_reply_handler(reply_handler_cb cb, void* ctx);
  // Effects: Registers a handler that takes reply messages

  void register_global_commit(global_commit_handler_cb cb, void* ctx);
  // Effects:: Registers a handler that is called when a batch is committed

  size_t num_correct_replicas() const;
  size_t f() const;
  void set_f(ccf::NodeId f);
  View view() const;
  bool is_primary() const;
  int primary() const;
  int primary(View view) const;
  void send(Message* m, int i);
  Seqno get_last_executed() const;
  int my_id() const;

  bool shutdown();
  // Effects: Shuts down replica writing a checkpoint to disk.

  bool restart(FILE* i);
  // Effects: Restarts the replica from the checkpoint in "i"

  bool delay_vc();
  // Effects: Returns true iff view change should be delayed.

  void start_vtimer_if_request_waiting();
  // Effects: Starts the view change timer if needed

  Big_req_table* big_reqs();
  // Effects: Returns the replica's big request table.

  void receive_message(const uint8_t* data, uint32_t size);
  // Effects: Use when messages are passed to Replica rather than replica
  // polling

  bool compare_execution_results(const ByzInfo& info, Pre_prepare* pre_prepare);
  // Compare the merkle root and batch ctx between the pre-prepare and the
  // the corresponding fields in info after execution

  bool apply_ledger_data(const std::vector<uint8_t>& data);
  // Effects: Entries are deserialized and requests are executed if they are
  // able to If not any requests are cleared from the request queues

  void init_state();
  void recv_start();

  static bool pre_verify(Message* m);
  template <class T>
  static bool gen_pre_verify(Message* m);

  void handle(Request* m);

private:
  friend class State;

  //
  // Message handlers:
  //

  void handle(Reply* m);
  void handle(Pre_prepare* m);
  void handle(Prepare* m);
  void handle(Commit* m);
  void handle(Checkpoint* m);
  void handle(View_change* m);
  void handle(New_view* m);
  void handle(View_change_ack* m);
  void handle(Status* m);
  void handle(New_key* m);
  void handle(Fetch* m);
  void handle(Data* m);
  void handle(Meta_data* m);
  void handle(Meta_data_d* m);
  void handle(Query_stable* m);
  void handle(Reply_stable* m);
  void handle(New_principal* m);
  // Effects: Execute the protocol steps associated with the arrival
  // of the argument message.

  static void vtimer_handler(void* owner);
  static void stimer_handler(void* owner);
  static void btimer_handler(void* owner);
  static void rec_timer_handler(void* owner);
  static void ntimer_handler(void* owner);
#ifdef DEBUG_SLOW
  static void debug_slow_timer_handler(void* owner);
#endif
  // Effects: Handle timeouts of corresponding timers.

  //
  // Auxiliary methods used by primary to send messages to the replica
  // group:
  //
  void send_pre_prepare(bool do_not_wait_for_batch_size = false);
  // Effects: Sends a Pre_prepare message

  void send_prepare(Seqno seqno, std::optional<ByzInfo> info = std::nullopt);
  // Effects: Sends a prepare message if appropriate.
  // If ByzInfo is provided there is no need to execute since execution has
  // already happened and relative information resides in info

  void send_commit(Seqno s, bool send_only_to_self = false);

  void send_null();
  // Send a pre-prepare with a null request if the system is idle

  //
  // Miscellaneous:
  //
  bool execute_read_only(Request* m);
  // Effects: If some request that was tentatively executed did not
  // commit yet (i.e. last_tentative_execute < last_executed), returns
  // false.  Otherwise, returns true, executes the command in request
  // "m" (provided it is really read-only and does not require
  // non-deterministic choices), and sends a reply to the client

  void execute_committed(bool was_f_0 = false);
  // Effects: Executes as many commands as possible by calling
  // execute_prepared; sends Checkpoint messages when needed and
  // manipulates the wait timer. If was_f_0 is set to true the certificate check
  // assumes that only 1 response is needed even if f != 0 when execute
  // committed is called

  void set_min_pre_prepare_batch_size();
  // Effects: Sets the min_pre_prepare_batch_size based on
  // historical information.

  void execute_prepared(bool committed = false);
  // Effects: Sends back replies that have been executed tentatively
  // to the client. The replies are tentative unless "committed" is true.

  bool execute_tentative(Pre_prepare* pp, ByzInfo& info);
  // Effects: Tentatively executes as many commands as possible. It
  // extracts requests to execute commands from a message "m"; calls
  // exec_command for each command; and sends back replies to the
  // client. The replies are tentative unless "committed" is true.

  void create_recovery_reply(
    int client_id, int last_tentative_execute, Byz_rep& outb);
  // Handle recovery requests, i.e., requests from replicas,
  // differently.  TODO: make more general to allow other types
  // of requests from replicas.

  void right_pad_contents(Byz_rep& outb);

  void mark_stable(Seqno seqno, bool have_state);
  // Requires: Checkpoint with sequence number "seqno" is stable.
  // Effects: Marks it as stable and garbage collects information.
  // "have_state" should be true iff the replica has a the stable
  // checkpoint.

  void fetch_state_outside_view_change();
  // Effects: initiates state fetching without a view change

  void new_state(Seqno seqno);
  // Effects: Updates this to reflect that the checkpoint with
  // sequence number "seqno" was fetch.

  void recover();
  // Effects: Recover replica.

  Pre_prepare* prepared_pre_prepare(Seqno s);
  // Effects: Returns non-zero iff there is a pre-prepare pp that prepared for
  // sequence number "s" (in this case it returns pp).

  Pre_prepare* committed(Seqno s, bool was_f_0 = false);
  // Effects: Returns non-zero iff there is a pre-prepare pp that committed for
  // sequence number "s" (in this case it returns pp).

  bool has_complete_new_view() const;
  // Effects: Returns true iff the replica has complete new-view
  // information for the current view.

  template <class T>
  bool in_w(T* m);
  // Effects: Returns true iff the message "m" has a sequence number greater
  // than last_stable and less than or equal to last_stable+max_out.

  template <class T>
  bool in_wv(T* m);
  // Effects: Returns true iff "in_w(m)" and "m" has the current view.

  template <class T>
  void gen_handle(Message* m);
  // Effects: Handles generic messages.

  template <class T>
  void retransmit(T* m, Time cur, Time tsent, Principal* p);
  // Effects: Retransmits message m (and re-authenticates it) if
  // needed. cur should be the current time.

  bool retransmit_rep(Reply* m, Time& cur, Time* tsent, Principal* p);

  void send_new_key();
  // Effects: Calls Node's send_new_key, adjusts timer and cleans up
  // stale messages.

  void enforce_bound(Seqno b);
  // Effects: Ensures that there is no information above bound "b".

  void enforce_view(View rec_view);
  // Effects: If replica is corrupt, sets its view to rec_view and
  // ensures there is no information for a later view in its.

  void try_end_recovery();
  // Effects: Ends recovery if all the conditions are satisfied

  void recv_process_one_msg(Message* m);
  // Helper functions when receiving a message. This can be used
  // when polling for a new message or we have a new message
  // passed to us.

  void dump_state(std::ostream& os);
  // logs the replica state for debugging

  //
  // Instance variables:
  //
  Seqno next_pp_seqno; // Sequence number to attribute to next protocol message,
                       // only valid if I am the primary.

  // These control batching. congestion_window controls how many pre-prepares
  // are sent before the previous batch completes execution. For the LAN, 1 is a
  // good setting but for WAN scenarios it should be increased to increase
  // parallelism. The primary waits for min_pre_prepare_batch_size requests to
  // include in the batch before sending the next pre-prepare, or for the
  // timeout max_pre_prepare_request_batch_wait_ms to expire.
  // min_pre_prepare_batch_size is adjusted dynamically with a lower bound of
  // min_min_pre_prepare_batch_size. num_look_back_to_set_batch_size batches is
  // the number of past batches used to compute min_pre_prepare_batch_size. The
  // settings below work well a LAN with congestion_window 1. In the WAN with
  // congestion window > 1, setting min_min_pre_prepare_batch_size to
  // Max_requests_in_batch and waiting for max_pre_prepare_request_batch_wait_ms
  // before sending each pre-prepare works better.
  static int const congestion_window = 1;
  static int min_pre_prepare_batch_size;
  static int const min_min_pre_prepare_batch_size = 1;
  static int const num_look_back_to_set_batch_size = 10;
  static int const max_pre_prepare_request_batch_wait_ms = 2;

  // Logging variables used to measure average batch size
  int nbreqs; // The number of requests executed in current interval
  int nbrounds; // The number of rounds of BFT executed in current interval

  Seqno last_stable; // Sequence number of last stable state.
  Seqno low_bound; // Low bound on request sequence numbers that may
                   // be accepted in current view.

  Seqno last_prepared; // Sequence number of highest prepared request
  Seqno last_executed; // Sequence number of last executed message.
  Seqno last_tentative_execute; // Sequence number of last message tentatively
                                // executed.

  // Sets and logs to keep track of messages received. Their size
  // is equal to max_out.
  Req_queue rqueue; // For read-write requests.
  Req_queue ro_rqueue; // For read-only requests

  Log<Prepared_cert> plog;

  Big_req_table brt; // Table with big requests
  friend class Big_req_table;

  Log<Certificate<Commit>> clog;
  Log<Certificate<Checkpoint>> elog;

  // Set of stable checkpoint messages above my window.
  std::unordered_map<int, std::unique_ptr<Checkpoint>> stable_checkpoints;

  // Last replies sent to each principal.
#ifdef ENFORCE_EXACTLY_ONCE
  Rep_info_exactly_once replies;
#else
  Rep_info replies;
#endif

  // used to register a callback for a client proxy to collect replies sent to
  // this replica
  reply_handler_cb rep_cb;
  void* rep_cb_ctx;

  // used to callback when we have committed a batch
  global_commit_handler_cb global_commit_cb;
  void* global_commit_ctx;

  std::unique_ptr<LedgerWriter> ledger_writer;
  std::unique_ptr<LedgerReplay> ledger_replay;

  // State abstraction manages state checkpointing and digesting
  State state;

  ITimer* stimer; // Timer to send status messages periodically.
  Time last_status; // Time when last status message was sent

  ITimer* btimer; // Timer to make sure pre_prepare batches are sent if we do
                  // not have a full batch
  //
  // View changes:
  //
  View_info vi; // View-info abstraction manages information about view changes
  ITimer* vtimer; // View change timer
  int cid_vtimer; // client id of first request in queue when vtimer started
  Request_id
    rid_vtimer; // request id of first request in queue when vtimer started
  bool limbo; // True iff moved to new view but did not start vtimer yet.
  bool has_nv_state; // True iff replica's last_stable is sufficient
                     // to start processing requests in new view.

  //
  // Proactive recovery
  //
  // Recovery timer. TODO: Timeout should be generated by watchdog
  ITimer* rtimer;
  bool rec_ready; // True iff replica is ready to recover
  bool recovering; // True iff replica is recovering.
  bool vc_recovering; // True iff replica exited limbo for a view after it
                      // started recovery
  bool corrupt; // True iff replica's data was found to be corrupt.

  ITimer* ntimer; // Timer to trigger transmission of null requests when system
                  // is idle
  // Estimation of the maximum stable checkpoint at any non-faulty replica
  Stable_estimator se;
  Query_stable* qs; // Message sent for estimation; qs != 0 iff replica is
                    // estimating the  maximum stable checkpoint

  Request* rr; // Outstanding recovery request or null if
               // there is no outstanding recovery request.
  Certificate<Reply> rr_reps; // Certificate with replies to recovery request.

  Seqno recovery_point; // Seqno_max if not known
  Seqno max_rec_n; // Maximum sequence number of a recovery request in state.

#ifdef DEBUG_SLOW
  ITimer* debug_slow_timer; // Used to dump state when requests take too long to
                            // execute
#endif

  //
  // Pointers to various functions.
  //
  ExecCommand exec_command;

  void (*non_det_choices)(Seqno, Byz_buffer*);
  int max_nondet_choice_len;

  //
  // Statistics to set pre_prepare batch info
  //
  std::unordered_map<Seqno, uint64_t> requests_per_batch;
  std::list<uint64_t> max_pending_reqs;
};

// Pointer to global replica object.
extern Replica* replica;

inline int Replica::max_nd_bytes() const
{
  return max_nondet_choice_len;
}

inline int Replica::used_state_bytes() const
{
  return replies.size();
}

inline void Replica::modify(void* mem, int size)
{
  state.cow((char*)mem, size);
}

inline void Replica::modify_index(int bindex)
{
  state.cow_single(bindex);
}

inline bool Replica::has_complete_new_view() const
{
  return v == 0 || (has_nv_state && vi.has_complete_new_view(v));
}

template <class T>
inline void Replica::gen_handle(Message* m)
{
  T* n;
  if (T::convert(m, n))
  {
    handle(n);
  }
  else
  {
    delete m;
  }
}

inline Big_req_table* Replica::big_reqs()
{
  return &brt;
}
