// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "certificate.h"
#include "node.h"
#include "parameters.h"
#include "pre_prepare.h"
#include "pre_prepare_info.h"
#include "prepare.h"
#include "types.h"

#include <sys/time.h>

class Prepared_cert
{
public:
  Prepared_cert();
  // Effects: Creates an empty prepared certificate.

  ~Prepared_cert();
  // Effects: Deletes certificate and all the messages it contains.

  bool add(Prepare* m);
  // Effects: Adds "m" to the certificate and returns true provided
  // "m" satisfies:
  // 1. there is no message from "m.id()" in the certificate
  // 2. "m->verify() == true"
  // 3. if "prepare_cert.cvalue() != 0", "prepare_cert.cvalue()->match(m)";
  // otherwise, it has no effect on this and returns false.  This
  // becomes the owner of "m" (i.e., no other code should delete "m"
  // or retain pointers to "m".)

  bool add(Pre_prepare* m);
  // Effects: Adds "m" to the certificate and returns true provided
  // "m" satisfies:
  // 1. there is no prepare from the calling principal in the certificate
  // 2. "m->verify() == true"

  bool add_mine(Prepare* m);
  // Requires: The identifier of the calling principal is "m->id()",
  // it is not the primary for "m->view(), and "mine()==0".
  // Effects: If "cvalue() != 0" and "!cvalue()->match(m)", it has no
  // effect and returns false. Otherwise, adds "m" to the certificate
  // and returns. This becomes the owner of "m"

  bool add_mine(Pre_prepare* m);
  // Requires: The identifier of the calling principal is "m->id()",
  // it is the primary for "m->view()", and it has no message in
  // certificate.
  // Effects: Adds "m" to certificate and returns true.

  void add_old(Pre_prepare* m);
  // Requires: There is no pre-prepare in this
  // Effects: Adds a pre-prepare message macthing this from an old
  // view.

  void add(Digest& d, int i);
  // Effects: If there is a pre-prepare message in this whose i-th
  // reference to a big request is d, records that d is cached and may
  // make the certificate complete.

  void update();
  // Update f if needed

  Prepare* my_prepare();
  Prepare* my_prepare(Time& t);
  Pre_prepare* my_pre_prepare();
  Pre_prepare* my_pre_prepare(Time& t);
  // Effects: If the calling replica has a prepare/pre_prepare message
  // in the certificate, returns a pointer to that message and sets
  // "t" (if supplied) to the time at which the message was
  // last sent.  Otherwise, it has no effect and returns 0.

  int num_correct();
  // Effects: Returns number of prepares in certificate that are known
  // to be correct.

  bool is_complete(bool was_f_0 = false);
  // Effects: Returns true iff the certificate is complete.

  bool is_pp_complete();
  // Effects: Returns true iff the pre-prepare-info is complete.

  bool is_pp_correct();
  // Effects: Returns true iff there are f prepares with same digest
  // as pre-prepare.

  Pre_prepare* pre_prepare() const;
  // Effects: Returns the pre-prepare in the certificate (or null if
  // the certificate contains no such message.)

  const BR_map& missing_reqs() const;
  // Effects: Returns a bit map with a bit reset for each request that is
  // missing in pre-prepare.

  Pre_prepare* rem_pre_prepare();
  // Effects: Returns the pre-prepare in the certificate and removes it

  Prepare* prepare() const;
  // Effects: If there is a correct prepare value returns it;
  // otherwise returns 0.

  Pre_prepare_info const* prep_info() const;
  // Effects: Returns a pointer to the pre-prepare info in this.

  void mark_stale();
  // Effects: Discards all messages in certificate except mine.

  void clear();
  // Effects: Discards all messages in certificate

  bool is_empty() const;
  // Effects: Returns true iff the certificate is empty

  void dump_state(std::ostream& os);
  // Effects: dumps state for debugging

  struct PrePrepareProof
  {
    std::vector<uint8_t> cert;
    PbftSignature signature;
  };

  const std::unordered_map<int, PrePrepareProof>& get_pre_prepared_cert_proof()
    const;

private:
  Certificate<Prepare> prepare_cert;
  std::unordered_map<int, PrePrepareProof> pre_prepare_proof;
  Pre_prepare_info pp_info;
  Time t_sent; // time at which pp was sent (if I am primary)
  bool primary; // true iff pp was added with add_mine
};

inline void Prepared_cert::update()
{
  prepare_cert.update();
}

inline bool Prepared_cert::add(Prepare* m)
{
  int id = m->id();
  auto principal = pbft::GlobalState::get_node().get_principal(id);
  if (!principal)
  {
    LOG_INFO_FMT(
      "Principal with id {} has not been configured yet, rejecting prepare",
      id);
    delete m;
    return false;
  }

#ifdef SIGN_BATCH
  PbftSignature& digest_sig = m->digest_sig();
  PrePrepareProof proof;
  std::copy(
    std::begin(digest_sig), std::end(digest_sig), std::begin(proof.signature));
#endif

  bool result = prepare_cert.add(m);

#ifdef SIGN_BATCH
  if (result)
  {
    proof.cert = principal->get_cert();
    pre_prepare_proof.insert({id, proof});
  }
#endif
  return result;
}

inline bool Prepared_cert::add_mine(Prepare* m)
{
  PBFT_ASSERT(
    pbft::GlobalState::get_node().id() !=
        pbft::GlobalState::get_node().primary(m->view()) ||
      pbft::GlobalState::get_node().f() == 0,
    "Invalid Argument");
  return prepare_cert.add_mine(m);
}

inline bool Prepared_cert::add_mine(Pre_prepare* m)
{
  PBFT_ASSERT(
    pbft::GlobalState::get_node().id() ==
      pbft::GlobalState::get_node().primary(m->view()),
    "Invalid Argument");
  PBFT_ASSERT(!pp_info.pre_prepare(), "Invalid state");
  prepare_cert.update();
  pp_info.add_complete(m);
  primary = true;
  t_sent = ITimer::current_time();
  return true;
}

inline void Prepared_cert::add_old(Pre_prepare* m)
{
  PBFT_ASSERT(pp_info.pre_prepare() == 0, "Invalid state");
  pp_info.add(m);
}

inline void Prepared_cert::add(Digest& d, int i)
{
  pp_info.add(d, i);
}

inline Prepare* Prepared_cert::my_prepare(Time& t)
{
  return prepare_cert.mine(t);
}
inline Prepare* Prepared_cert::my_prepare()
{
  Time t;
  return prepare_cert.mine(t);
}

inline Pre_prepare* Prepared_cert::my_pre_prepare(Time& t)
{
  if (primary)
  {
    if (pp_info.pre_prepare())
    {
      t = t_sent;
    }
    return pp_info.pre_prepare();
  }
  return 0;
}

inline Pre_prepare* Prepared_cert::my_pre_prepare()
{
  Time t;
  return my_pre_prepare(t);
}

inline const Pre_prepare_info* Prepared_cert::prep_info() const
{
  return &pp_info;
}

inline int Prepared_cert::num_correct()
{
  return prepare_cert.num_correct();
}

inline bool Prepared_cert::is_complete(bool was_f_0)
{
  if (pp_info.is_complete())
  {
    if (prepare_cert.num_complete() == 0)
    {
      return true;
    }

    return prepare_cert.is_complete() &&
      (was_f_0 || pp_info.pre_prepare()->match(prepare_cert.cvalue()));
  }

  return false;
}

inline bool Prepared_cert::is_pp_complete()
{
  return pp_info.is_complete();
}

inline Pre_prepare* Prepared_cert::pre_prepare() const
{
  return pp_info.pre_prepare();
}

inline const BR_map& Prepared_cert::missing_reqs() const
{
  return pp_info.missing_reqs();
}

inline Pre_prepare* Prepared_cert::rem_pre_prepare()
{
  Pre_prepare* ret = pp_info.pre_prepare();
  pp_info.zero();
  return ret;
}

inline Prepare* Prepared_cert::prepare() const
{
  return prepare_cert.cvalue();
}

inline void Prepared_cert::mark_stale()
{
  if (!is_complete())
  {
    if (
      pbft::GlobalState::get_node().primary() !=
      pbft::GlobalState::get_node().id())
    {
      pp_info.clear();
    }
    prepare_cert.mark_stale();
  }
}

inline void Prepared_cert::clear()
{
  pp_info.clear();
  t_sent = 0;
  prepare_cert.clear();
  primary = false;
}
