// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "Certificate.h"
#include "Node.h"
#include "libbyz.h"
#include "types.h"

class Reply;
class Request;
class ITimer;

class Client : public Node
{
public:
  Client(const NodeInfo& node_info, INetwork* network);
  // Effects: Creates a new Client object using the information in
  // node_info.

  virtual ~Client();
  // Effects: Deallocates all storage associated with this.

  bool send_request(Request* req);
  // Effects: Sends request m to the service. Returns FALSE iff two
  // consecutive request were made without waiting for a reply between
  // them.

  Reply* recv_reply();
  // Effects: Blocks until it receives enough reply messages for
  // the previous request. returns a pointer to the reply. The caller is
  // responsible for deallocating the request and reply messages.

  Request_id get_rid() const;
  // Effects: Returns the current outstanding request identifier. The request
  // identifier is updated to a new value when the previous message is
  // delivered to the user.

  void reset();
  // Effects: Resets client state to ensure independence of experimental
  // points.

private:
  Request* out_req; // Outstanding request
  bool need_auth; // Whether to compute new authenticator for out_req
  Request_id out_rid; // Identifier of the outstanding request
  int n_retrans; // Number of retransmissions of out_req
  int rtimeout; // Timeout period in msecs

  // Maximum retransmission timeout in msecs
  static const int Max_rtimeout = 200;

  // Minimum retransmission timeout after retransmission
  // in msecs
  static const int Min_rtimeout = 100;

  void increase_retransmission_timeout();
  void decrease_retransmission_timeout();

  Cycle_counter latency; // Used to measure latency.

  // Multiplier used to obtain retransmission timeout from avg_latency
  static const int Rtimeout_mult = 4;

  Certificate<Reply> t_reps; // Certificate with tentative replies (size 2f+1)
  Certificate<Reply> c_reps; // Certificate with committed replies (size f+1)

  static void rtimer_handler(void* owner);
  ITimer* rtimer; // Retransmission timer

  void retransmit();
  // Effects: Retransmits any outstanding request and last new-key message.

  void send_new_key();
  // Effects: Calls Node's send_new_key, and cleans up stale replies in
  // certificates.
};

inline Request_id Client::get_rid() const
{
  return out_rid;
}
