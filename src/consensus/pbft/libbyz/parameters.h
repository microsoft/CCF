// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include <cstddef>

const int Max_num_replicas = 32;

// Interval in sequence space between "checkpoint" states, i.e.,
// states that are checkpointed and for which Checkpoint messages are
// sent.
const int checkpoint_interval = 64;

// Maximum number of messages for which protocol can be
// simultaneously in progress, i.e., messages with sequence number
// higher than last_stable+max_out are ignored. It is required that
// max_out > checkpoint_interval. Otherwise, the algorithm will be
// unable to make progress.
const int max_out = 512;

static const size_t Max_requests_in_batch = 256;

static constexpr size_t max_sig_size = 64; // in bytes

static const size_t num_senders = 2;
// number of sender threads

static const size_t num_receivers_replicas = 1;
// number of threads that handle receiving messages from replicas

static const size_t num_receivers_clients = 3;
// number of threads that handle receiving messages from clients

// use public key crypto to sign checkpoint messages
#define USE_PKEY_CHECKPOINTS

// use public key crypto to sign view-change and new-view messages
#define USE_PKEY_VIEW_CHANGES

// enforce exactly once semantics for request execution
//#define ENFORCE_EXACTLY_ONCE
