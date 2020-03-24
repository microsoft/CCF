// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

//#include <sys/time.h>
//#include <sys/resource.h>
#include "cycle_counter.h"
#include "message_tags.h"
#include "types.h"

#include <unistd.h>
#include <vector>

struct Recovery_stats
{
  Long shutdown_time; // Cycles spent in shutdown
  Long reboot_time;
  Long restart_time; // Cycles spent in restart
  Long est_time; // Cycles for estimation procedure
  Long nk_time; // Cycles to send new key message
  Long rr_time; // Cycles to send the recovery request

  Long check_time; // Cycles spent checking pages
  Long num_checked; // Number of pages checked

  Long fetch_time; // Cycles spent fetching during recovery
  Long num_fetched; // Number of data blocks received
  Long num_fetched_a; // Number of data blocks accepted
  Long refetched; // Number of blocks refetched
  Long num_fetches;
  Long meta_data_fetched; // Number of meta-data[d] messages received
  Long meta_data_fetched_a; // Number of meta-data[d] messages accepted
  Long meta_data_bytes;
  Long meta_datad_fetched; // Number of meta-data-d messages received
  Long meta_datad_fetched_a; // Number of meta-data-d messages accepted
  Long meta_datad_bytes; // Number of bytes in meta-data-d blocks
  Long meta_data_refetched; // Number of meta-data blocks refetched

  Long sys_cycles; // Cycles spent handling syscalls during rec.

  Long rec_bin;
  Long rec_bout;

  Long rec_time; // Cycles to complete recovery

  Recovery_stats();
  void print_stats();
  void zero_stats();
};

struct Statistics
{
  // Number of cycles after statistics were zeroed.
  Cycle_counter cycles_after_zero;

  long reply_auth; // Number of replies authenticated
  Cycle_counter reply_auth_cycles; // and number of cycles.

  long reply_auth_ver; // Number of replies verified
  Cycle_counter reply_auth_ver_cycles; // and number of cycles.

  //
  // Digests:
  //
  long num_digests; // Number of digests
  Cycle_counter digest_cycles; // and number of cycles.

  long pp_digest; // Number of times pre-prepare digests are computed
  Cycle_counter pp_digest_cycles; // and number of cycles.

  //
  // Signatures
  //
  long num_sig_gen; // Number of signature generations
  Cycle_counter sig_gen_cycles; // and number of cycles.

  long num_sig_ver; // Number of signature verifications
  Cycle_counter sig_ver_cycles; // and number of cycles.

  //
  // Recovery:
  //
  std::vector<Recovery_stats> rec_stats;
  long rec_counter; // Number of recoveries
  long rec_overlaps; // Number of recoveries that ended after executing recovery
                     // request for next replica.
  long incomplete_recs; // Number of recoveries ended by my next recovery
  Cycle_counter rec_time; // Total cycles for recovery
  Cycle_counter est_time; // Cycles for estimation procedure
  Cycle_counter nk_time; // Cycles to send new key message
  Cycle_counter rr_time; // Cycles to send the recovery request
  long num_checked; // Number of pages checked
  Cycle_counter check_time; // Cycles spent checking pages
  Cycle_counter shutdown_time; // Cycles spent in shutdown
  Cycle_counter restart_time; // Cycles spent in restart
  Cycle_counter reboot_time;

  //
  // Bandwidth:
  //
  long long bytes_in;
  long long bytes_out;

  //
  // View changes:
  //

  //
  // State:
  //
  long num_fetches; // Number of times fetch is started
  long num_fetched; // Number of data blocks fetched
  long num_fetched_a; // Number of data blocks accepted
  long refetched; // Number of data refetched while checking
  long meta_data_fetched; // Number of meta-data messages received
  long meta_data_fetched_a; // Number of meta-data messages accepted
  long meta_data_bytes; // Number of bytes in meta-data blocks
  long meta_datad_fetched; // Number of meta-data-d messages received
  long meta_datad_fetched_a; // Number of meta-data-d messages accepted
  long meta_datad_bytes; // Number of bytes in meta-data-d blocks
  long meta_data_refetched;
  long num_ckpts; // Number of checkpoints computed
  Cycle_counter ckpt_cycles; // and number of cycles.
  long num_rollbacks; // Number of rollbacks
  Cycle_counter rollback_cycles; // and number of cycles
  long num_cows; // Number of copy-on-writes
  Cycle_counter cow_cycles; // and number of cycles
  Cycle_counter fetch_cycles; // Cycles fetching state (w/o waiting)

  long cache_hits;
  long cache_misses;
  long last_executed;

  long count_pre_prepare_batch_timer;

  //
  // Syscalls:
  //
  long num_recvfrom; // Number of recvfroms
  long num_recv_success; // Number of successful recvfroms
  Cycle_counter recvfrom_cycles; // and number of cycles

  long num_sendto; // Number of sendtos
  Cycle_counter sendto_cycles; // and number of cycles

  Cycle_counter select_cycles; // Number of cycles in select
  long select_success; // Number of times select exits with fd set
  long select_fail; // Number of times select exits with fd not set.

  Cycle_counter handle_timeouts_cycles;

  long req_retrans; // Number of request retransmissions

  size_t message_counts_retransmitted[Max_message_tag];
  size_t message_counts_out[Max_message_tag];
  size_t message_counts_in[Max_message_tag];

  size_t batch_size_histogram[Max_requests_in_batch];
  size_t sum_batch_size;

  Statistics();
  void print_stats();
  void zero_stats();

  void init_rec_stats();
  void end_rec_stats();
};

extern Statistics stats;

#ifndef INSIDE_ENCLAVE
#  define PRINT_STATS
#endif

#ifdef PRINT_STATS
#  define START_CC(x) stats.x.start()
#  define STOP_CC(x) stats.x.stop()
#  define INCR_OP(x) stats.x++
#  define INCR_CNT(x, y) (stats.x += (y))
#  define INIT_REC_STATS() stats.init_rec_stats()
#  define END_REC_STATS() stats.end_rec_stats()
#else
#  define START_CC(x)
#  define STOP_CC(x)
#  define INCR_OP(x)
#  define INCR_CNT(x, y)
#  define INIT_REC_STATS()
#  define END_REC_STATS()
#endif
