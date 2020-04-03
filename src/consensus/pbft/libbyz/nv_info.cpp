// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "nv_info.h"

#include "k_max.h"
#include "new_view.h"
#include "pre_prepare.h"
#include "replica.h"
#include "status.h"
#include "view_change.h"
#include "view_change_ack.h"
#include "view_info.h"

//
// NV_info::VC_info methods:
//

NV_info::VC_info::VC_info() : ack_count(0), req_sum(false) {}

void NV_info::VC_info::clear()
{
  vc = 0;
  ack_count = 0;
  ack_reps.reset();
  req_sum = false;
}

NV_info::Req_sum::Req_sum() {}

NV_info::Req_sum::Req_sum(
  View v, Digest d, int n_le, int id, int n_proofs, int n_pproofs) :
  v(v),
  d(d),
  n_proofs(n_proofs),
  n_pproofs(n_pproofs),
  n_le(n_le),
  id(id)
{
  pp_info.zero();
}

NV_info::Req_sum::~Req_sum()
{
  pp_info.zero();
}
// This is necessary to prevent any pre-prepare in pp_info from being
// deallocated. Because Req_sum assignment only performs a shallow
// copy.

//
// NV_info methods:
//

NV_info::NV_info() : v(0), nv(0), vc_target(0), vc_cur(0), vcs(64)
{
  chosen_ckpt = -1;
  max = -1;
  base = -1;
  n_complete = 0;
  is_complete = false;
  nv_sent = zero_time();
}

NV_info::~NV_info()
{
  clear();
}

void NV_info::clear()
{
  v = 0;
  delete nv;
  nv = 0;
  vc_target = 0;

  for (int i = 0; i < vcs.size(); i++)
  {
    vcs[i].clear();
  }
  vc_cur = 0;

  ckpts.clear();
  chosen_ckpt = -1;
  max = -1;
  base = -1;
  min = -1;
  nv_sent = zero_time();
  for (int i = 0; i < reqs.size(); i++)
  {
    for (int j = 0; j < reqs[i].size(); j++)
    {
      reqs[i][j].pp_info.clear();
    }
    reqs[i].clear();
  }
  reqs.clear();
  comp_reqs.clear();

  n_complete = 0;
  is_complete = false;
}

void NV_info::make_complete(View vi)
{
  v = vi;
  is_complete = true;
}

View_change* NV_info::mark_stale(int id)
{
  std::unique_ptr<View_change> pres;
  if (!is_complete)
  {
    pres = std::move(vcs[id].vc);
    vcs[id].vc = 0;
    View ov = v;

    clear();

    if (ov > 0 && pbft::GlobalState::get_node().primary(ov) == id)
    {
      // The primary recreates its state to allow the construction of
      // a complete new-view for this view.
      New_view* nv = new New_view(ov);
      add(nv, vi);

      PBFT_ASSERT(pres != 0, "Invalid state");
      if (can_add(pres.get()))
      {
        add(std::move(pres));
      }
    }
  }
  return pres.release();
}

bool NV_info::add(New_view* m, View_info* parent)
{
  PBFT_ASSERT(parent != 0, "Invalid argument");

  if (m->view() <= v)
  {
    delete m;
    return false;
  }

  // Remove any old information.
  if (v != 0)
  {
    clear();
  }

  // Add m to this.
  v = m->view();
  nv = m;
  vi = parent;

  // Set vc_target.
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    Digest vd;
    if (m->view_change(i, vd))
    {
      vc_target++;
    }
  }

  return true;
}

bool NV_info::can_add(View_change* m)
{
  PBFT_ASSERT(m->view() == v, "Invalid argument");

  int vcid = m->id();
  if (vcs[vcid].vc != 0 || is_complete)
  {
    return false;
  }

  bool is_primary = pbft::GlobalState::get_node().primary(v) ==
    pbft::GlobalState::get_node().id();

  if (!is_primary)
  {
    Digest d;
    if (!nv->view_change(vcid, d) || d != m->digest())
    {
      return false;
    }
  }

  return true;
}

void NV_info::add(std::unique_ptr<View_change> m)
{
  int vcid = m->id();
  vcs[vcid].vc = std::move(m);
  auto vc = vcs[vcid].vc.get();
  vc_cur++;

  bool is_primary = pbft::GlobalState::get_node().primary(v) ==
    pbft::GlobalState::get_node().id();
#ifdef USE_PKEY_VIEW_CHANGES
  if (is_primary)
  {
    nv->add_view_change(vcid, vc->digest());
    summarize(vc);
  }
#else
  if (is_primary && vcid == pbft::GlobalState::get_node().id())
  {
    nv->add_view_change(vcid, vc->digest());
    summarize(vc);
  }
#endif

  if (!is_primary && vc_cur == vc_target)
  {
    // We have all the needed view-change messages. Check if they
    // form a valid new-view.
    if (!check_new_view())
    {
      // Primary is faulty.
      LOG_FAIL << "Primary " << pbft::GlobalState::get_node().primary(v)
               << " is faulty" << std::endl;
    }
  }
}

bool NV_info::add(View_change_ack* m)
{
  PBFT_ASSERT(m->verify() && m->view() == v, "Invalid argument");

  int vci = m->vc_id();
  int mid = m->id();

  bool is_primary = pbft::GlobalState::get_node().primary(v) ==
    pbft::GlobalState::get_node().id();

  if (is_complete)
  {
    return false;
  }

  Digest d;
  bool in_nv = nv->view_change(vci, d);

  if (!is_primary)
  {
    if (!in_nv)
    {
      return false;
    }
  }
  else
  {
    if (!vcs[vci].vc)
    {
      return false;
    }

    d = vcs[vci].vc->digest();
  }

  if (!in_nv && m->vc_digest() == d && !vcs[vci].ack_reps.test(mid))
  {
    vcs[vci].ack_reps.set(mid);
    vcs[vci].ack_count++;

    if (
      vcs[vci].ack_count ==
        pbft::GlobalState::get_node().num_correct_replicas() - 2 &&
      pbft::GlobalState::get_node().primary(v) ==
        pbft::GlobalState::get_node().id())
    {
      // This view change has enough acks: add it to the new-view.
      auto vc = vcs[vci].vc.get();
      nv->add_view_change(vci, vc->digest());
      summarize(vc);
    }
  }
  delete m;
  return true;
}

void NV_info::summarize(View_change* vc)
{
  PBFT_ASSERT(!is_complete, "Invalid state");

  int size = ckpts.size();
  bool was_chosen = chosen_ckpt >= 0;
  bool match = false;
  int n_le = 0;
  Seqno max_seqno = vc->max_seqno();

  Digest vclc;
  Seqno vcn = vc->last_stable();
  vc->ckpt(vcn, vclc); // vclc is null if vc has no checkpoint digest

  for (int i = 0; i < size; i++)
  {
    Ckpt_sum& cur = ckpts[i];

    if (cur.n == vcn && cur.d == vclc)
    {
      match = true;
      cur.n_proofs++;
      cur.n_le++;
      if (vc->max_seqno() > cur.max_seqno)
      {
        cur.max_seqno = vc->max_seqno();
      }
    }
    else
    {
      Digest d;
      if (vc->ckpt(cur.n, d) && d == cur.d)
      {
        cur.n_proofs++;
      }

      if (cur.n > vcn)
      {
        cur.n_le++;
        if (vc->max_seqno() > cur.max_seqno)
        {
          cur.max_seqno = vc->max_seqno();
        }
      }
      else if (cur.n < vcn)
      {
        n_le++;
        if (cur.max_seqno > max_seqno)
        {
          max_seqno = cur.max_seqno;
        }
      }
    }

    if (
      cur.n_proofs >= pbft::GlobalState::get_node().f() + 1 &&
      cur.n_le >= pbft::GlobalState::get_node().num_correct_replicas())
    {
      choose_ckpt(i);
    }
  }

  if (!match && !vclc.is_zero())
  {
    // vc has checkpoints and no entry matches its last checkpoint: add a new
    // one.
    Ckpt_sum ns;
    ns.n = vcn;
    ns.d = vclc;
    ns.n_le = n_le + 1;
    ns.max_seqno = max_seqno;
    ns.id = vc->id();
    ns.n_proofs = 0;

    // Search view-changes in new-view for proofs
    Digest d;
    for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
    {
      if (nv->view_change(i) && vcs[i].vc->ckpt(vcn, d) && d == vclc)
      {
        ns.n_proofs++;
      }
    }

    ckpts.push_back(ns);

    if (
      ns.n_proofs >= pbft::GlobalState::get_node().f() + 1 &&
      ns.n_le >= pbft::GlobalState::get_node().num_correct_replicas())
    {
      choose_ckpt(ckpts.size() - 1);
    }
  }

  if (was_chosen && !is_complete)
  {
    summarize_reqs(vc);
    pbft::GlobalState::get_replica().send_status();
  }
}

void NV_info::choose_ckpt(int index)
{
  PBFT_ASSERT(
    pbft::GlobalState::get_node().primary(v) ==
      pbft::GlobalState::get_node().id(),
    "Invalid state");
  PBFT_ASSERT(index >= 0 && index < ckpts.size(), "Out of bounds");

  Ckpt_sum& cur = ckpts[index];
  PBFT_ASSERT(
    cur.n_proofs >= pbft::GlobalState::get_node().f() + 1 &&
      cur.n_le >= pbft::GlobalState::get_node().num_correct_replicas(),
    "Invalid argument");

  if (chosen_ckpt < 0)
  {
    chosen_ckpt = index;
    min = cur.n;
    base = cur.n + 1;
    max = cur.max_seqno + 1;

    reqs.resize(reqs.size() + max - base);
    comp_reqs.resize(comp_reqs.size() + max - base, 0);

    for (int i = 0; i < comp_reqs.size(); i++)
    {
      comp_reqs[i] = -1;
    }

    // Summarize requests for all view-change messages in new-view.
    for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
    {
      if (nv->view_change(i))
      {
        summarize_reqs(vcs[i].vc.get());
        if (is_complete)
        {
          return;
        }
      }
    }
  }
  else if (ckpts[chosen_ckpt].n < cur.n)
  {
    // Adjust n_complete to account for change of range.
    for (Seqno i = min + 1; i <= cur.n; i++)
    {
      if (comp_reqs[i - base] >= 0)
      {
        n_complete--;
      }
    }

    chosen_ckpt = index;
    min = cur.n;
    if (cur.max_seqno + 1 < max)
    {
      max = cur.max_seqno + 1;
    }
  }

  if (n_complete == max - min - 1)
  {
    is_complete = true;
    make_new_view();
  }
}

void NV_info::check_comp(Req_sum& cur, Seqno i, int j)
{
  PBFT_ASSERT(!is_complete, "Invalid state");

  if (
    comp_reqs[i - base] < 0 &&
    cur.n_proofs >= pbft::GlobalState::get_node().f() + 1 &&
    cur.n_le >= pbft::GlobalState::get_node().num_correct_replicas())
  {
    if (!cur.pp_info.is_complete())
    {
      if (cur.pp_info.pre_prepare() == 0)
      {
        // Check if the missing pre-prepare is in the log.
        Pre_prepare* opp = vi->pre_prepare(i, cur.d);

        if (opp)
        {
          cur.pp_info.add(opp->clone(v));
          cur.n_pproofs = pbft::GlobalState::get_node().num_of_replicas();
        }
      }
    }

    if (
      cur.n_pproofs <= pbft::GlobalState::get_node().f() &&
      vi->prepare(i, cur.d))
    {
      // If node sent a prepare for this digest in the past, we do not
      // need more positive proofs.
      cur.n_pproofs = pbft::GlobalState::get_node().num_of_replicas();
    }

    if (
      cur.v < 0 ||
      (cur.pp_info.is_complete() &&
       cur.n_pproofs > pbft::GlobalState::get_node().f()))
    {
      comp_reqs[i - base] = j;
      n_complete++;
    }
    else
    {
      return;
    }
  }

  // If we gathered enough information, make the new-view message.
  if (n_complete == max - min - 1)
  {
    is_complete = true;

    if (
      pbft::GlobalState::get_replica().primary(v) ==
      pbft::GlobalState::get_replica().id())
    {
      make_new_view();
    }
    else
    {
      // Update backups's state to reflect the new view.
      Digest d;
      auto vc = vcs[nv->which_picked(nv->min())].vc.get();
      Seqno n = vc->last_stable();
      vc->ckpt(n, d);
      PBFT_ASSERT(!d.is_zero(), "Invalid state");
      Seqno ks = known_stable();
      pbft::GlobalState::get_replica().process_new_view(n, d, nv->max(), ks);
    }
  }
}

Seqno NV_info::known_stable()
{
  PBFT_ASSERT(is_complete, "Invalid state");

  Seqno* maxs = new Seqno[pbft::GlobalState::get_node().num_of_replicas()];

  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    maxs[i] = (vcs[i].vc != 0) ? vcs[i].vc->last_stable() : 0;
  }

  Seqno max_stable1 = K_max(
    pbft::GlobalState::get_node().f() + 1,
    maxs,
    pbft::GlobalState::get_node().num_of_replicas(),
    Seqno_max);
  PBFT_ASSERT(max_stable1 <= min, "Invalid state");

  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    Digest d;
    Seqno n;
    if (vcs[i].vc && vcs[i].vc->last_ckpt(d, n))
    {
      maxs[i] = n;
    }
    else
    {
      maxs[i] = 0;
    }
  }

  Seqno max_stable2 = K_max(
    pbft::GlobalState::get_node().num_correct_replicas(),
    maxs,
    pbft::GlobalState::get_node().num_of_replicas(),
    Seqno_max);

  if (max_stable2 > min)
  {
    max_stable2 = min;
  }

  delete[] maxs;

  return (max_stable1 > max_stable2) ? max_stable1 : max_stable2;
}

void NV_info::get_proofs(Req_sum& cur, View_change* vc, Seqno i)
{
  bool prepared;
  View v, lv;
  Digest d;
  if (!vc->proofs(i, v, lv, d, prepared))
  {
    if (i > vc->last_stable() && cur.v < 0)
    {
      cur.n_proofs++;
    }
    return;
  }

  if (prepared)
  {
    if ((lv >= cur.v) && (d == cur.d))
    {
      cur.n_proofs++;
      cur.n_pproofs++;
      PBFT_ASSERT(
        !cur.r_pproofs.test(vc->id()), "Counting pproof more than once");
      cur.r_pproofs.set(vc->id());
    }
  }
  else
  {
    if ((v >= cur.v) && (d == cur.d))
    {
      cur.n_proofs++;
      cur.n_pproofs++;
      PBFT_ASSERT(
        !cur.r_pproofs.test(vc->id()), "Counting pproof more than once");
      cur.r_pproofs.set(vc->id());
    }
    else if (cur.v <= lv)
    {
      cur.n_proofs++;
    }
  }
}

void NV_info::summarize_reqs(View_change* vc)
{
  PBFT_ASSERT(vc != 0 && nv->view_change(vc->id()), "Invalid argument");
  PBFT_ASSERT(!vcs[vc->id()].req_sum, "Invalid argument");
  PBFT_ASSERT(!is_complete, "Invalid state");

  vcs[vc->id()].req_sum = true;

  Seqno i = (min > vc->last_stable()) ? min : vc->last_stable();
  for (i = i + 1; i < max; i++)
  {
    assert(reqs.size() > i - base);
    std::vector<Req_sum>& reqsi = reqs[i - base];
    bool match = false;
    int n_le = 0;

    Digest rd;
    View rv = vc->req(i, rd);

    for (int j = 0; j < reqsi.size(); j++)
    {
      Req_sum& cur = reqsi[j];

      if (cur.v == rv && cur.d == rd)
      {
        match = true;
        cur.n_proofs++;
        cur.n_pproofs++;
        PBFT_ASSERT(
          !cur.r_pproofs.test(vc->id()), "Counting pproof more than once");
        cur.r_pproofs.set(vc->id());
        cur.n_le++;
      }
      else
      {
        // Update cur.n_proofs
        get_proofs(cur, vc, i);

        // Update cur.n_le
        if (cur.v > rv)
        {
          cur.n_le++;
        }
        else if (cur.v < rv)
        {
          n_le++;
        }
      }

      check_comp(cur, i, j);
      if (is_complete)
      {
        return;
      }
    }

    if (!match)
    {
      // No entry matches this request: add a new one.
      Req_sum& cur = reqsi.emplace_back(rv, rd, n_le + 1, vc->id(), 0, 0);

      // Search view-changes for proofs
      for (int j = 0; j < pbft::GlobalState::get_node().num_of_replicas(); j++)
      {
        if (vcs[j].req_sum)
        {
          get_proofs(cur, vcs[j].vc.get(), i);
        }
      }

      check_comp(cur, i, reqsi.size() - 1);
      if (is_complete)
      {
        return;
      }
    }
  }
}

void NV_info::make_new_view()
{
  PBFT_ASSERT(
    pbft::GlobalState::get_node().primary(v) ==
      pbft::GlobalState::get_node().id(),
    "Invalid state");
  PBFT_ASSERT(is_complete, "Invalid state");
  PBFT_ASSERT(nv_sent == zero_time(), "Invalid state");

  nv->set_min(min);

  // Pick the checkpoint
  nv->pick(ckpts[chosen_ckpt].id, min);

  // Pick the requests.
  for (Seqno i = min + 1; i < max; i++)
  {
    PBFT_ASSERT(comp_reqs[i - base] >= 0, "Invalid state");
    Req_sum& cur = reqs[i - base][comp_reqs[i - base]];

    PBFT_ASSERT(cur.pp_info.is_complete() || cur.v == -1, "Invalid state");
    nv->pick(cur.id, i);
  }

  nv->set_max(max);

  nv_sent = ITimer::current_time();

  // Update replica's state to reflect new-view.
  Seqno ks = known_stable();
  pbft::GlobalState::get_replica().process_new_view(
    min, ckpts[chosen_ckpt].d, nv->max(), ks);
}

bool NV_info::check_new_view()
{
  PBFT_ASSERT(
    pbft::GlobalState::get_node().primary(v) !=
      pbft::GlobalState::get_node().id(),
    "Invalid state");

  // Check chosen checkpoint.
  int cid = nv->which_picked(nv->min());
  auto vc = vcs[cid].vc.get();
  min = vc->last_stable();
  if (min != nv->min())
  {
    return false;
  }
  base = min + 1;

  Digest d;
  if (!vc->ckpt(min, d))
  {
    return false;
  }

  int n_le = 1;
  int n_proofs = 1;

  // Search view-changes for proofs
  Digest dd;
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    if (i != cid && vcs[i].vc)
    {
      if (vcs[i].vc->ckpt(min, dd) && dd == d)
      {
        n_proofs++;
      }
      if (vcs[i].vc->last_stable() <= min)
      {
        n_le++;
      }
    }
  }

  if (
    n_proofs < pbft::GlobalState::get_node().f() + 1 ||
    n_le < pbft::GlobalState::get_node().num_correct_replicas())
  {
    return false;
  }

  chosen_ckpt = 0;

  // Checkpoint is correct. Check the value of nv->max(): this value
  // is correct if there exist 2f+1 view change messages that do not
  // propose any pre-prepared or prepared request with sequence number
  // greater than or equal to nv->max().
  int n_lt = 0;
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    auto vc = vcs[i].vc.get();
    if (vc == 0)
    {
      continue;
    }

    if (vc->max_seqno() < nv->max())
    {
      n_lt++;
    }
  }

  if (n_lt < pbft::GlobalState::get_node().num_correct_replicas())
  {
    return false;
  }

  // nv->max() is correct. Check requests.
  max = nv->max();

  if (base == nv->max())
  {
    is_complete = true;
    Seqno ks = known_stable();
    pbft::GlobalState::get_replica().process_new_view(min, d, nv->max(), ks);
    return true;
  }

  reqs.resize(reqs.size() + max - min - 1);
  comp_reqs.resize(comp_reqs.size() + max - min - 1, 0);

  for (int i = 0; i < comp_reqs.size(); i++)
  {
    comp_reqs[i] = -1;
  }

  for (Seqno i = base; i < nv->max(); i++)
  {
    int vci = nv->which_picked(i);
    vc = vcs[vci].vc.get();

    if (i <= vc->last_stable())
    {
      return false;
    }

    Digest d;
    View v = vc->req(i, d);
    Req_sum& cur = reqs[i - base].emplace_back(v, d, 0, vc->id(), 0, 0);
    // Search view-changes for proofs
    for (int j = 0; j < pbft::GlobalState::get_node().num_of_replicas(); j++)
    {
      if (vcs[j].vc && i > vcs[j].vc->last_stable())
      {
        get_proofs(cur, vcs[j].vc.get(), i);
        Digest dd;
        if (vcs[j].vc->req(i, dd) <= cur.v)
        {
          cur.n_le++;
        }
      }
    }

    if (
      cur.n_proofs < pbft::GlobalState::get_node().f() + 1 ||
      cur.n_le < pbft::GlobalState::get_node().num_correct_replicas())
    {
      return false;
    }
    else
    {
      check_comp(cur, i, 0);
    }
  }

  return true;
}

Pre_prepare* NV_info::fetch_request(Seqno n, Digest& d, View& prev_view)
{
  PBFT_ASSERT(is_complete, "Invalid state");
  PBFT_ASSERT(n > nv->min() && n < nv->max(), "Invalid arguments");

  Pre_prepare* pp = 0;
  Digest null;
  View pv = vcs[nv->which_picked(n)].vc->req(n, d);

  if (pv >= 0 && d != null)
  {
    // Normal request
    pp = reqs[n - base][comp_reqs[n - base]].pp_info.pre_prepare();
    reqs[n - base][comp_reqs[n - base]].pp_info.zero();
    prev_view = pv;
    PBFT_ASSERT(pp != 0, "Invalid state");
  }
  else
  {
    // Null request
    Req_queue empty;
    size_t requests_in_batch;
    pp = new Pre_prepare(v, n, empty, requests_in_batch, 0);
    pp->set_digest();
    d = pp->digest();
    prev_view = v;
  }

  if (
    pbft::GlobalState::get_node().primary(v) ==
    pbft::GlobalState::get_node().id())
  {
    pp->re_authenticate();
  }

  return pp;
}

void NV_info::set_received_vcs(Status* m)
{
  if (
    pbft::GlobalState::get_node().primary(v) !=
    pbft::GlobalState::get_node().id())
  {
    // Not primary.
    Digest d;
    for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
    {
      if (vcs[i].vc || !nv->view_change(i, d))
      {
        m->mark_vcs(i);
      }
    }
  }
  else
  {
    for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
    {
      if (vcs[i].vc && nv->view_change(i))
      {
        m->mark_vcs(i);
      }
    }
  }
}

void NV_info::set_missing_pps(Status* m)
{
  for (Seqno i = base; i < max; i++)
  {
    if (comp_reqs[i - base] >= 0)
    {
      continue;
    }

    std::vector<Req_sum>& reqsi = reqs[i - base];
    View vpp = v;
    bool need_proofs = false;
    BR_map mrmap(1);

    // For each sequence number, determine the minimum view vpp for which
    // there is a missing pre-prepare for a proven request.
    for (int j = 0; j < reqsi.size(); j++)
    {
      Req_sum& cur = reqsi[j];
      if (
        cur.v >= 0 && cur.v < vpp &&
        cur.n_proofs >= pbft::GlobalState::get_node().f() + 1 &&
        cur.n_le >= pbft::GlobalState::get_node().num_correct_replicas())
      {
        vpp = cur.v;

        if (cur.n_pproofs <= pbft::GlobalState::get_node().f())
        {
          need_proofs = true;
        }
        else if (cur.pp_info.pre_prepare())
        {
          mrmap &= cur.pp_info.missing_reqs();
        }
      }
    }

    // Ask for any pre-prepares for that sequence number with view
    // greater than or equal to vpp.
    if (vpp < v)
    {
      m->append_pps(vpp, i, mrmap, need_proofs);
    }
  }
}

void NV_info::add_missing(Pre_prepare* pp)
{
  Seqno ppn = pp->seqno();

  if (chosen_ckpt >= 0 && ppn > min && ppn < max && comp_reqs[ppn - base] < 0)
  {
    std::vector<Req_sum>& reqspp = reqs[ppn - base];

    for (int j = 0; j < reqspp.size(); j++)
    {
      Req_sum& cur = reqspp[j];

      if (cur.d == pp->digest())
      {
        if (cur.pp_info.pre_prepare() == 0 && pp->check_digest())
        {
          cur.pp_info.add(pp->clone(v));
          check_comp(cur, ppn, j);
        }
        break;
      }
    }
  }

  delete pp;
}

void NV_info::add_missing(Digest& rd, Seqno ppn, int i)
{
  if (chosen_ckpt >= 0 && ppn > min && ppn < max && comp_reqs[ppn - base] < 0)
  {
    std::vector<Req_sum>& reqspp = reqs[ppn - base];

    for (int j = 0; j < reqspp.size(); j++)
    {
      Req_sum& cur = reqspp[j];
      cur.pp_info.add(rd, i);
      check_comp(cur, ppn, j);
      if (complete())
      {
        break;
      }
    }
  }
}

void NV_info::add_missing(Prepare* p)
{
  Seqno pn = p->seqno();

  if (chosen_ckpt >= 0 && pn > min && pn < max && comp_reqs[pn - base] < 0)
  {
    std::vector<Req_sum>& reqsp = reqs[pn - base];

    for (int j = 0; j < reqsp.size(); j++)
    {
      Req_sum& cur = reqsp[j];

      if (cur.d == p->digest())
      {
        if (
          cur.n_pproofs <= pbft::GlobalState::get_node().f() &&
          !cur.r_pproofs.test(p->id()))
        {
          cur.n_pproofs++;
          PBFT_ASSERT(
            !cur.r_pproofs.test(p->id()), "Counting pproof more than once");
          cur.r_pproofs.set(p->id());
          check_comp(cur, pn, j);
        }
        break;
      }
    }
  }

  delete p;
}

void NV_info::mark_stable(Seqno ls)
{
  if (
    v > 0 && !is_complete && chosen_ckpt >= 0 && ls >= max &&
    pbft::GlobalState::get_node().primary(v) !=
      pbft::GlobalState::get_node().id())
  {
    // If I am not the primary, I can use the fact that ls is stable
    // to trim the number of pre-prepares I need proofs for.
    is_complete = true;
    pbft::GlobalState::get_replica().process_new_view(ls, Digest(), ls, ls);
  }
}

void NV_info::dump_state(std::ostream& os)
{
  os << " v: " << v << " nv: " << (void*)nv << " vc_target: " << vc_target
     << " vc_cur: " << vc_cur << " is_complete: " << is_complete
     << " nv_sent: " << nv_sent << std::endl;

  os << " View changes vcs: " << std::endl;
  for (int i = 0; i < pbft::GlobalState::get_node().num_of_replicas(); i++)
  {
    os << " i: " << i << " vc: " << (void*)vcs[i].vc.get()
       << " ack_count: " << vcs[i].ack_count << " ack_reps: " << vcs[i].ack_reps
       << " req_sum: " << vcs[i].req_sum << std::endl;
  }

  os << " Checkpoints chosen_ckpt: " << chosen_ckpt << " min: " << min
     << " max: " << max << " base: " << base << " ckpts: " << std::endl;
  for (int i = 0; i < ckpts.size(); i++)
  {
    os << " i: " << i << " n: " << ckpts[i].n
       << " digest hash: " << ckpts[i].d.hash()
       << " n_proofs: " << ckpts[i].n_proofs << " n_le: " << ckpts[i].n_le
       << " max_seqno: " << ckpts[i].max_seqno << " id: " << ckpts[i].id
       << std::endl;
  }

  os << " Requests n_complete: " << n_complete << " comp_reqs:" << std::endl;
  for (int i = 0; i < comp_reqs.size(); i++)
  {
    os << " comp_reqs[" << i << "]: " << comp_reqs[i];
  }
  os << std::endl;

  os << " reqs: " << std::endl;
  for (int i = 0; i < reqs.size(); i++)
  {
    auto& reqs_i = reqs[i];
    for (int j = 0; j < reqs_i.size(); j++)
    {
      auto& reqs_ij = reqs_i[j];
      os << " req_sum (" << i << "," << j << ") v: " << reqs_ij.v
         << " digest hash: " << reqs_ij.d.hash()
         << " n_proofs: " << reqs_ij.n_proofs
         << " n_pproofs: " << reqs_ij.n_pproofs << " n_le: " << reqs_ij.n_le
         << " id: " << reqs_ij.id << std::endl;
      reqs_ij.pp_info.dump_state(os);
    }
  }
}
