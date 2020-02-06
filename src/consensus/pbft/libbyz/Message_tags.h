// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

//
// Each message type is identified by one of the tags in the set below.
//

const short Free_message_tag = 0; // Used to mark free message reps.
                                  // A valid message may never use this tag.
const short Request_tag = 1;
const short Reply_tag = 2;
const short Pre_prepare_tag = 3;
const short Prepare_tag = 4;
const short Commit_tag = 5;
const short Checkpoint_tag = 6;
const short Status_tag = 7;
const short View_change_tag = 8;
const short New_view_tag = 9;
const short View_change_ack_tag = 10;
const short New_key_tag = 11;
const short Meta_data_tag = 12;
const short Meta_data_d_tag = 13;
const short Data_tag = 14;
const short Fetch_tag = 15;
const short Query_stable_tag = 16;
const short Reply_stable_tag = 17;
const short Network_open_tag = 18;
const short Append_entries_tag = 19;
const short Max_message_tag = 20;

// Message used for testing are in the 100+ range
const short New_principal_tag = 100;
