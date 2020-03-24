// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "statistics.h"

#include "message_tags.h"
#include "pbft_assert.h"
#include "time_types.h"
#include "timer.h"

#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>

Statistics stats;

Statistics::Statistics() : rec_stats(20)
{
  zero_stats();
}

void Statistics::zero_stats()
{
#ifdef PRINT_STATS
  reply_auth = 0;
  reply_auth_cycles.reset();
  reply_auth_ver = 0;
  reply_auth_ver_cycles.reset();

  num_digests = 0;
  digest_cycles.reset();
  pp_digest = 0;
  pp_digest_cycles.reset();

  num_sig_gen = 0;
  sig_gen_cycles.reset();

  num_sig_ver = 0;
  sig_ver_cycles.reset();

  rec_counter = 0;
  rec_stats.clear();
  rec_overlaps = 0;
  incomplete_recs = 0;
  rec_time.reset();
  est_time.reset();
  nk_time.reset();
  rr_time.reset();
  num_checked = 0;
  check_time.reset();
  shutdown_time.reset();
  restart_time.reset();
  reboot_time.reset();

  num_fetches = 0;
  num_fetched = 0;
  num_fetched_a = 0;
  refetched = 0;
  meta_data_fetched = 0;
  meta_data_fetched_a = 0;
  meta_data_bytes = 0;
  meta_datad_fetched = 0;
  meta_datad_fetched_a = 0;
  meta_datad_bytes = 0;
  meta_data_refetched = 0;
  num_ckpts = 0;
  ckpt_cycles.reset();
  num_rollbacks = 0;
  rollback_cycles.reset();
  num_cows = 0;
  cow_cycles.reset();
  fetch_cycles.reset();

  cache_hits = 0;
  cache_misses = 0;

  bytes_in = 0;
  bytes_out = 0;

  num_recvfrom = 0;
  num_recv_success = 0;
  recvfrom_cycles.reset();
  num_sendto = 0;
  sendto_cycles.reset();
  select_cycles.reset();
  select_success = 0;
  select_fail = 0;

  req_retrans = 0;

  for (int i = 0; i < Max_message_tag; i++)
  {
    message_counts_out[i] = 0;
    message_counts_in[i] = 0;
    message_counts_retransmitted[i] = 0;
  }

  for (int i = 0; i < Max_requests_in_batch; i++)
  {
    batch_size_histogram[i] = 0;
  }

  sum_batch_size = 0;

  handle_timeouts_cycles.reset();

  struct rusage ru;

  int ret = getrusage(RUSAGE_SELF, &ru);
  if (ret != 0)
  {
    PBFT_FAIL("getrusage failed");
  }

  cycles_after_zero.reset();
  cycles_after_zero.start();

  last_executed = 0;
  count_pre_prepare_batch_timer = 0;
#endif
}

void Statistics::print_stats()
{
#ifdef PRINT_STATS
  cycles_after_zero.stop();
  struct rusage ru_end;
  struct rusage ru;
  int ret = getrusage(RUSAGE_SELF, &ru_end);
  if (ret != 0)
  {
    PBFT_FAIL("getrusage failed");
  }

  printf("\nStatistics: \n");

  printf("\nCycles in this interval: %qd \n", cycles_after_zero.elapsed());

  printf("\nMessage counts out: \n");
  for (int i = 0; i < Max_message_tag; i++)
  {
    printf("tag: %d count: %ld \n", i, message_counts_out[i]);
  }

  printf("\nMessage counts in: \n");
  for (int i = 0; i < Max_message_tag; i++)
  {
    printf("tag: %d count: %ld \n", i, message_counts_in[i]);
  }

  printf("\nMessage counts retransmitted: \n");
  for (int i = 0; i < Max_message_tag; i++)
  {
    printf("tag: %d count: %ld \n", i, message_counts_retransmitted[i]);
  }

  printf(
    "\nAverage batch size: %f \n",
    (pp_digest) ? (float)sum_batch_size / pp_digest : 0);

  printf("\nBatch size histogram: \n");
  for (int i = 0; i < Max_requests_in_batch; i++)
  {
    printf("%d : %ld \n", i, batch_size_histogram[i]);
  }

  printf("\nRusage stats: \n");
  printf("User time = %f (sec) \n", diff_time(ru.ru_utime, ru_end.ru_utime));
  printf("System time = %f (sec) \n", diff_time(ru.ru_stime, ru_end.ru_stime));

  printf("\nReply MAC stats:\n");
  printf(
    "Generate = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    reply_auth_cycles.elapsed(),
    reply_auth_cycles.max_increment(),
    reply_auth);

  printf(
    "Verify = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    reply_auth_ver_cycles.elapsed(),
    reply_auth_ver_cycles.max_increment(),
    reply_auth_ver);

  printf("\nDigest stats:\n");
  printf(
    "Generate = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    digest_cycles.elapsed(),
    digest_cycles.max_increment(),
    num_digests);

  printf("\nSignature stats:\n");
  printf(
    "Generate = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    sig_gen_cycles.elapsed(),
    sig_gen_cycles.max_increment(),
    num_sig_gen);

  printf(
    "Verify = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    sig_ver_cycles.elapsed(),
    sig_ver_cycles.max_increment(),
    num_sig_ver);

  printf("\nPre_prepare digests and building:\n");
  printf(
    "Generate = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    pp_digest_cycles.elapsed(),
    pp_digest_cycles.max_increment(),
    pp_digest);

  printf("\nRecovery stats:\n");
  printf(
    "Recoveries = %ld overlaps = %ld incompletes = %ld\n",
    rec_counter,
    rec_overlaps,
    incomplete_recs);
  printf(
    "Total recovery time = %qd (cycles) %qd (max. op cycles)\n",
    rec_time.elapsed(),
    rec_time.max_increment());
  for (int i = 0; i < rec_counter; i++)
  {
    printf("Recovery %d: \n", i);
    rec_stats[i].print_stats();
  }

  printf("\nState stats:\n");
  printf("Num pages fetched = %ld \n", num_fetched);
  printf("Num meta_data fetched = %ld \n", meta_data_fetched);
  printf(
    "Checkpointing = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    ckpt_cycles.elapsed(),
    ckpt_cycles.max_increment(),
    num_ckpts);
  printf(
    "Cow = %qd (cycles)  %qd (max. op cycles) ops= %ld \n",
    cow_cycles.elapsed(),
    cow_cycles.max_increment(),
    num_cows);
  printf(
    "Rollbacking = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    rollback_cycles.elapsed(),
    rollback_cycles.max_increment(),
    num_rollbacks);
  printf("Fetch = %qd (cycles) \n", fetch_cycles.elapsed());

  printf(
    "Checkpoint Objects Cache: Hits %ld   / Misses %ld\n",
    cache_hits,
    cache_misses);

  printf("\nBandwidth stats:\n");
  printf("Bytes received = %qd Bytes sent = %qd\n", bytes_in, bytes_out);

  printf("\nSyscall stats:\n");
  printf(
    "Recvfrom = %qd (cycles) %qd (max. op cycles) ops= %ld success= %ld\n",
    recvfrom_cycles.elapsed(),
    recvfrom_cycles.max_increment(),
    num_recvfrom,
    num_recv_success);

  printf(
    "Sendto = %qd (cycles) %qd (max. op cycles) ops= %ld \n",
    sendto_cycles.elapsed(),
    sendto_cycles.max_increment(),
    num_sendto);

  printf(
    "Select = %qd (cycles) %qd (max. op cycles) success = %ld fail = %ld\n",
    select_cycles.elapsed(),
    select_cycles.max_increment(),
    select_success,
    select_fail);

  printf(
    "\nHandle timeouts = %qd (cycles) %qd (max. op cycles)\n",
    handle_timeouts_cycles.elapsed(),
    handle_timeouts_cycles.max_increment());

  printf("\nRequest retransmissions = %ld\n", req_retrans);

  printf("\nlast_executed = %ld\n", last_executed);

  printf(
    "\ncount_pre_prepare_batch_timer= %ld\n", count_pre_prepare_batch_timer);

  cycles_after_zero.start();
#endif
}

Recovery_stats::Recovery_stats()
{
  zero_stats();
}

void Statistics::init_rec_stats()
{
  rec_counter++;

  rec_stats.push_back(Recovery_stats());
  Recovery_stats& rs = rec_stats.back();

  rs.shutdown_time = shutdown_time.elapsed();
  rs.reboot_time = reboot_time.elapsed();
  rs.restart_time = restart_time.elapsed();
  rs.est_time = est_time.elapsed();
  rs.nk_time = nk_time.elapsed();
  rs.rr_time = rr_time.elapsed();

  rs.check_time = check_time.elapsed();
  rs.num_checked = num_checked;

  rs.fetch_time = fetch_cycles.elapsed();
  rs.num_fetched = num_fetched;
  rs.num_fetched_a = num_fetched_a;
  rs.refetched = refetched;
  rs.num_fetches = num_fetches;
  rs.meta_data_fetched = meta_data_fetched;
  rs.meta_data_fetched_a = meta_data_fetched_a;
  rs.meta_data_bytes = meta_data_bytes;
  rs.meta_datad_fetched = meta_datad_fetched;
  rs.meta_datad_fetched_a = meta_datad_fetched_a;
  rs.meta_datad_bytes = meta_datad_bytes;
  rs.meta_data_refetched = meta_data_refetched;

  rs.sys_cycles = select_cycles.elapsed() + sendto_cycles.elapsed() +
    recvfrom_cycles.elapsed();
  ;

  rs.rec_bin = bytes_in;
  rs.rec_bout = bytes_out;

  rs.rec_time = rec_time.elapsed();

  rec_time.start();
}

void Statistics::end_rec_stats()
{
  rec_time.stop();
  Recovery_stats& rs = rec_stats.back();

  rs.shutdown_time = shutdown_time.elapsed() - rs.shutdown_time;
  rs.reboot_time = reboot_time.elapsed() - rs.reboot_time;
  rs.restart_time = restart_time.elapsed() - rs.restart_time;
  rs.est_time = est_time.elapsed() - rs.est_time;
  rs.nk_time = nk_time.elapsed() - rs.nk_time;
  rs.rr_time = rr_time.elapsed() - rs.rr_time;

  rs.check_time = check_time.elapsed() - rs.check_time;
  rs.num_checked = num_checked - rs.num_checked;

  rs.fetch_time = fetch_cycles.elapsed() - rs.fetch_time;
  rs.num_fetched = num_fetched - rs.num_fetched;
  rs.num_fetched_a = num_fetched_a - rs.num_fetched_a;
  rs.refetched = refetched - rs.refetched;
  rs.num_fetches = num_fetches - rs.num_fetches;
  rs.meta_data_fetched = meta_data_fetched - rs.meta_data_fetched;
  rs.meta_data_fetched_a = meta_data_fetched_a - rs.meta_data_fetched_a;
  rs.meta_data_bytes = meta_data_bytes - rs.meta_data_bytes;
  rs.meta_datad_fetched = meta_datad_fetched - rs.meta_datad_fetched;
  rs.meta_datad_fetched_a = meta_datad_fetched_a - rs.meta_datad_fetched_a;
  rs.meta_datad_bytes = meta_datad_bytes - rs.meta_datad_bytes;
  rs.meta_data_refetched = meta_data_refetched - rs.meta_data_refetched;

  rs.sys_cycles = select_cycles.elapsed() + sendto_cycles.elapsed() +
    recvfrom_cycles.elapsed() - rs.sys_cycles;

  rs.rec_bin = bytes_in - rs.rec_bin;
  rs.rec_bout = bytes_out - rs.rec_bout;

  rs.rec_time = rec_time.elapsed() - rs.rec_time;
}

void Recovery_stats::zero_stats()
{
  shutdown_time = 0;
  reboot_time = 0;
  restart_time = 0;
  est_time = 0;
  nk_time = 0;
  rr_time = 0;

  check_time = 0;
  num_checked = 0;

  fetch_time = 0;
  num_fetched = 0;
  num_fetches = 0;
  meta_data_fetched = 0;
  meta_data_bytes = 0;

  sys_cycles = 0;

  rec_bin = 0;
  rec_bout = 0;

  rec_time = 0;
}

void Recovery_stats::print_stats()
{
  printf("Shutdown = %qd (us)\n", shutdown_time / clock_mhz);
  printf("Reboot = %qd (us)\n", reboot_time / clock_mhz);
  printf("Restart = %qd (us)\n", restart_time / clock_mhz);
  printf(
    "Estimation procedure = %ld (cycles) / %qd (us)\n",
    est_time,
    est_time / clock_mhz);
  printf("Send new key = %qd (us)\n", nk_time / clock_mhz);
  printf("Send rec. request = %qd (us)\n", rr_time / clock_mhz);
  printf(
    "Checking = %qd (us) num checked = %ld \n",
    check_time / clock_mhz,
    num_checked);
  printf(
    "Fetching = %qd (us) num fetches = %ld \n",
    fetch_time / clock_mhz,
    num_fetches);
  printf(
    "data: fetched = %ld accepted = %ld refetched = %ld \n",
    num_fetched,
    num_fetched_a,
    refetched);
  printf(
    "meta-data: fetched = %ld accepted = %ld bytes = %ld \n",
    meta_data_fetched,
    meta_data_fetched_a,
    meta_data_bytes);
  printf(
    "meta-data-d: fetched = %ld accepted = %ld bytes = %ld \n",
    meta_datad_fetched,
    meta_datad_fetched_a,
    meta_datad_bytes);
  printf("meta-data refetched = %ld \n", meta_data_refetched);

  printf("Handling syscalls = %qd (us) \n", sys_cycles / clock_mhz);
  printf("Total recovery time = %qd (us) \n", rec_time / clock_mhz);
  printf("Bytes in = %ld \n", rec_bin);
  printf("Bytes out = %ld \n", rec_bout);
}
