// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "digest.h"
#include "ds/dl_list.h"
#include "ds/thread_messaging.h"
#include "req_queue.h"
#include "types.h"

#include <list>
#include <unordered_map>
#include <vector>

class Request;

struct Waiting_pp
{
  Seqno n;
  View v;
  int i;
};

class BR_entry
{
public:
  inline BR_entry() : r(0), maxn(-1), maxv(-1), next(nullptr), prev(nullptr) {}
  inline ~BR_entry()
  {
    delete r;
  }

  Digest rd; // Request's digest
  Request* r; // Request or 0 is request not received
  // if r=0, Seqnos of pre-prepares waiting for request
  std::vector<Waiting_pp> waiting;
  Seqno maxn; // Maximum seqno of pre-prepare referencing request
  View maxv; // Maximum view in which this entry was marked useful

  BR_entry* next;
  BR_entry* prev;
};

class Big_req_table
{
  //
  // Overview: Table that holds entries for big requests. The entries
  // contain the requests digest and a pointer to the request or if
  // the request is not cached a list of pre-prepare messages the
  // reference the request. These entries are used to match
  // pre-prepares with their big requests. (Big requests are those
  // whose size is greater than Request::big_req_thresh.)
  //
public:
  Big_req_table();
  // Effects: Creates an empty table.

  Big_req_table(size_t num_of_replicas);

  ~Big_req_table();
  // Effects: Deletes table and any requests it references.

  void add_pre_prepare(Request* r, Seqno n, View v);
  // Effects: Records that request "r" is referenced by the
  // pre-prepare with sequence number "n" and that this information is
  // current in view "v".

  bool add_pre_prepare(Digest& rd, int i, Seqno n, View v);
  // Effects: Records that the i-th reference to a big request in the
  // pre-prepare with sequence number "n" is to the request with
  // digest "rd", and that this information is current in view
  // "v". Returns true if the request is in the table; otherwise,
  // returns false.

  void refresh_entry(Digest& rd, int i, Seqno n, View v);
  // Requires: There is an entry for rd in the table
  // Effects: Update entry to prevent discarding the request
  // when there is a view change to v.

  bool add_request(Request* r, bool verified = true);
  // Requires: r->size() > Request::big_req_thresh & verified == r->verify()
  // Effects: If there is an entry for digest "r->digest()", the entry
  // does not already contain a request and the authenticity of the
  // request can be verified, then it adds "r" to the entry, calls
  // "add_request" on each pre-prepare-info whose pre-prepare is
  // waiting on the entry, and returns true. Otherwise, returns false
  // and has no other effects (in particular it does not delete "r").

  Request* lookup(Digest& rd);
  // Effects: Returns the request in this with digest "rd" or 0 if
  // there is no such request.

  void clear();
  // Effects: Discards (deletes) all stored entries

  void mark_stable(Seqno ls, Req_queue& req_queue);
  // Effects: Discards entries that were only referred to by
  // pre-prepares that were discarded due to checkpoint "ls" becoming
  // stable. If an entry is in the req_queue it will not be removed.

  void view_change(View v);
  // Effects: Discards entries that were only referred to by
  // pre-prepares that were discarded due to view changing to view
  // "v".

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

  static const int Max_unmatched_requests_per_client = 1024 * 100;
  // Effect: The maximum number of requests we will store per client.
  // This functions as a LRU cache.

private:
  bool check_pcerts(BR_entry* bre);
  // Requires: pbft::GlobalState::get_replica().has_complete_new_view()
  // Effects: Returns true iff there is some pre-prepare in
  // bre->waiting that has f matching prepares in its prepared
  // certificate.

  void remove_unmatched(BR_entry* bre);
  // Requires: bre->r != 0
  // Effects: Removes bre->r from unmatched if it was not previously matched
  // to a pre-prepare.

  bool add_unmatched(BR_entry* e, Request*& old_req);
  // Effects: Adds r to the list of requests for the client if the request
  // id is greater than the largest in the list and returns true. If this causes
  // the number of requests to exceed Max_unmatched_requests_per_client,
  // Removes the last request in the list and returns it in old_req. Returns
  // false if r is not added to the list.

  std::unordered_map<Digest, BR_entry*, DigestHash> breqs;
  int max_entries; // Maximum number of entries allowed in the table.

  Seqno last_stable;
  View last_view;

  struct Unmatched_requests
  {
    Unmatched_requests() : num_requests(0) {}
    snmalloc::DLList<BR_entry> list;
    int num_requests;
  };

  // Map from client id to lists of requests that have no waiting pre-prepares
  std::unordered_map<int, Unmatched_requests> unmatched;
};
