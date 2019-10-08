// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "View_info.h"

#include "Big_req_table.h"
#include "K_max.h"
#include "New_view.h"
#include "Pre_prepare.h"
#include "Replica.h"
#include "Status.h"
#include "View_change.h"
#include "View_change_ack.h"
#include "pbft_assert.h"

View_info::VCA_info::VCA_info() : v(0), vacks(node->num_of_replicas(), nullptr)
{}

void View_info::VCA_info::clear()
{
  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    delete vacks[i];
    vacks[i] = 0;
  }
  v = 0;
}

View_info::View_info(int ident, View vi) :
  v(vi),
  id(ident),
  last_stable(0),
  oplog(max_out),
  last_views(node->num_of_replicas(), (View)0),
  last_vcs(node->num_of_replicas()),
  my_vacks(node->num_of_replicas(), nullptr),
  last_nvs(node->num_of_replicas())
{
  vacks.resize(node->num_of_replicas());
}

View_info::~View_info()
{
  for (int i = 0; i < my_vacks.size(); i++)
  {
    delete my_vacks[i];
  }
}

void View_info::add_complete(Pre_prepare* pp)
{
  PBFT_ASSERT(pp->view() == v, "Invalid argument");

  OReq_info& ri = oplog.fetch(pp->seqno());
  PBFT_ASSERT(pp->view() >= 0 && pp->view() > ri.v, "Invalid argument");

  ri.clear();
  ri.v = pp->view();
  ri.lv = ri.v;
  ri.d = pp->digest();
  ri.m = pp;
}

void View_info::add_incomplete(Seqno n, Digest const& d)
{
  OReq_info& ri = oplog.fetch(n);

  if (ri.d == d)
  {
    // Message matches the one in the log
    if (ri.m != 0)
    {
      // Logged message was prepared
      ri.lv = v;
    }
    else
    {
      ri.v = v;
    }
  }
  else
  {
    // Message is different from the one in log
    if (ri.m != 0)
    {
      delete ri.m;
      ri.m = 0;
    }
    else
    {
      ri.lv = ri.v;
    }

    // Remember last f()+2 digests.
    View minv = View_max;
    int mini = 0;
    for (int i = 0; i < node->f() + 2; i++)
    {
      if (ri.ods[i].d == ri.d)
      {
        ri.ods[i].v = ri.lv;
        mini = -1;
        break;
      }

      if (ri.ods[i].v < minv)
      {
        mini = i;
        minv = ri.ods[i].v;
      }
    }

    if (mini >= 0)
    {
      ri.ods[mini].d = ri.d;
      ri.ods[mini].v = ri.lv;
    }

    ri.d = d;
    ri.v = v;
  }
}

void View_info::send_proofs(Seqno n, View vi, int dest)
{
  if (oplog.within_range(n))
  {
    OReq_info& ri = oplog.fetch(n);
    std::shared_ptr<Principal> p = node->get_principal(dest);
    if (!p)
    {
      return;
    }
    for (int i = 0; i < node->f() + 2; i++)
    {
      if (ri.ods[i].v >= vi)
      {
        Prepare prep(ri.ods[i].v, n, ri.ods[i].d, p.get());
        node->send(&prep, dest);
      }
    }
  }
}

Pre_prepare* View_info::pre_prepare(Seqno n, Digest& d)
{
  if (oplog.within_range(n))
  {
    OReq_info& ri = oplog.fetch(n);
    if (ri.m && ri.d == d)
    {
      PBFT_ASSERT(
        ri.m->digest() == ri.d && ri.m->seqno() == n, "Invalid state");
      return ri.m;
    }
  }

  return 0;
}

Pre_prepare* View_info::pre_prepare(Seqno n, View v)
{
  if (oplog.within_range(n))
  {
    OReq_info& ri = oplog.fetch(n);
    if (ri.m && ri.v >= v)
    {
      PBFT_ASSERT(ri.m->seqno() == n, "Invalid state");
      return ri.m;
    }
  }

  return 0;
}

bool View_info::prepare(Seqno n, Digest& d)
{
  // Effects: Returns true iff "this" logs that this replica sent a
  // prepare with digest "d" for sequence number "n".

  if (oplog.within_range(n))
  {
    OReq_info& ri = oplog.fetch(n);

    if (ri.d == d)
    {
      return true;
    }

    for (int i = 0; i < node->f() + 2; i++)
    {
      if (ri.ods[i].d == d)
      {
        return true;
      }
    }
  }

  return false;
}

void View_info::discard_old()
{
  // Discard view-changes, view-change acks, and new views with view
  // less than "v"
  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    if (last_vcs[i] && last_vcs[i]->view() < v)
    {
      last_vcs[i] = 0;
    }

    delete my_vacks[i];
    my_vacks[i] = 0;

    if (vacks[i].v < v)
    {
      vacks[i].clear();
      vacks[i].v = v;
    }

    if (last_nvs[i].view() < v)
    {
      last_nvs[i].clear();
    }
  }
}

void View_info::view_change(View vi, Seqno last_executed, State* state)
{
  v = vi;

  discard_old();

  // Create my view-change message for "v".
  auto vc = std::make_unique<View_change>(v, last_stable, id);

  // Add checkpoint information to the message.
  for (Seqno i = last_stable; i <= last_executed; i += checkpoint_interval)
  {
    Digest dc;
    if (state->digest(i, dc))
    {
      vc->add_checkpoint(i, dc);
    }
  }

  Big_req_table* brt = replica->big_reqs();

  // Add request information to the message.
  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    OReq_info& ri = oplog.fetch(i);

    // Null requests are not added to message.
    if (ri.v >= 0)
    {
      vc->add_request(i, ri.v, ri.lv, ri.d, ri.m != 0);

      if (ri.m)
      {
        // Update replica's brt to prevent discarding of big requests
        // referenced by logged pre-prepares.
        for (int j = 0; j < ri.m->num_big_reqs(); j++)
        {
          brt->refresh_entry(ri.m->big_req_digest(j), j, i, v);
        }
      }
    }
  }

  // Discard stale big reqs.
  brt->view_change(v);

  vc->re_authenticate();
  vc_sent = ITimer::current_time();

  LOG_INFO << "Sending view change view: " << vc->view() << std::endl;
  node->send(vc.get(), Node::All_replicas);

  // Record that this message was sent.
  vc->trim();
  last_vcs[id] = std::move(vc);
  last_views[id] = v;

  int primv = node->primary(v);
  if (primv != id)
  {
#ifndef USE_PKEY_VIEW_CHANGES
    // If we are not the primary, send view-change acks for messages in
    // last_vcs with view v.
    for (int i = 0; i < node->num_of_replicas(); i++)
    {
      auto lvc = last_vcs[i];
      if (lvc && lvc->view() == v && i != id && i != primv)
      {
        View_change_ack* vack = new View_change_ack(v, id, i, lvc->digest());
        my_vacks[i] = vack;

        LOG_INFO << "Sending view change ack for " << vack->view() << " from "
                 << i << "\n";
        node->send(vack, primv);
      }
    }
#endif
  }
  else
  {
    // If we are the primary create new view info for "v"
    NV_info& n = last_nvs[id];
    PBFT_ASSERT(n.view() <= v, "Invalid state");

    // Create an empty new-view message and add it to "n". Information
    // will later be added to "n/nv".
    New_view* nv = new New_view(v);
    n.add(nv, this);

    // Move any view-change messages for view "v" to "n".
    for (int i = 0; i < node->num_of_replicas(); i++)
    {
      auto vc = last_vcs[i].get();
      if (vc && vc->view() == v && n.can_add(vc, true))
      {
        n.add(std::move(last_vcs[i]), true);
        last_vcs[i] = 0;
      }
    }
#ifndef USE_PKEY_VIEW_CHANGES
    // Move any view-change acks for messages in "n" to "n"
    for (int i = 0; i < node->num_of_replicas(); i++)
    {
      VCA_info& vaci = vacks[i];
      if (vaci.v == v)
      {
        for (int j = 0; j < node->num_of_replicas(); j++)
        {
          if (vaci.vacks[j] && n.add(vaci.vacks[j]))
            vaci.vacks[j] = 0;
        }
      }
    }
#endif
  }
}

bool View_info::add(std::unique_ptr<View_change> vc)
{
  int vci = vc->id();
  int vcv = vc->view();

  if (vcv < v)
  {
    return false;
  }

  // Try to match vc with a new-view message.
  NV_info& n = last_nvs[node->primary(vcv)];
  bool stored = false;
  if (n.view() == vcv)
  {
    // There is a new-view message corresponding to "vc"
    bool verified = vc->verify();
    stored = n.can_add(vc.get(), verified);
    if (stored)
    {
      n.add(std::move(vc), verified);
    }

#ifndef USE_PKEY_VIEW_CHANGES
    if (stored && id == node->primary(v) && vcv == v)
    {
      // Try to add any buffered view-change acks that match vc to "n"
      for (int i = 0; i < node->num_of_replicas(); i++)
      {
        VCA_info& vaci = vacks[i];
        if (vaci.v == v && vaci.vacks[vci] && n.add(vaci.vacks[vci]))
        {
          vaci.vacks[vci] = 0;
        }
      }
    }
#endif

    if (verified && vcv > last_views[vci])
    {
      last_views[vci] = vcv;
    }
  }
  else
  {
    // There is no matching new-view.
    if (vcv > last_views[vci] && vc->verify())
    {
      last_vcs[vci] = std::move(vc);
      last_views[vci] = vcv;
      stored = true;

#ifndef USE_PKEY_VIEW_CHANGES
      int primv = node->primary(v);
      if (id != primv && vci != primv && vcv == v)
      {
        // Send view-change ack.
        LOG_INFO << " Sending view change ack for " << v << " from " << vci
                 << "\n";
        View_change_ack* vack = new View_change_ack(v, id, vci, vc->digest());
        PBFT_ASSERT(my_vacks[vci] == 0, "Invalid state");

        my_vacks[vci] = vack;
        node->send(vack, primv);
      }
#endif
    }
  }
  return stored;
}

void View_info::add(New_view* nv)
{
  int nvi = nv->id();
  int nvv = nv->view();

  if (nvv >= v && nv->verify())
  {
    NV_info& n = last_nvs[nvi];
    if (nv->view() > n.view())
    {
      bool stored = n.add(nv, this);
      if (stored)
      {
        // Move any view-change messages for view "nvv" to "n".
        for (int i = 0; i < last_vcs.size(); i++)
        {
          auto vc = last_vcs[i].get();
          if (vc && vc->view() == nvv && n.can_add(vc, true))
          {
            n.add(std::move(last_vcs[i]), true);
          }
        }
      }
      return;
    }
  }

  LOG_INFO << "Rejected new view message for " << nv->view() << " from "
           << nv->id() << "\n";

  delete nv;
}

void View_info::add(View_change_ack* vca)
{
  int vci = vca->vc_id();
  int vcv = vca->view();

  if (vca->verify())
  {
    int primvcv = node->primary(vcv);

    NV_info& n = last_nvs[primvcv];
    if (n.view() == vcv && n.add(vca))
    {
      // There is a new-view message corresponding to "vca"
      return;
    }

    if (id == primvcv)
    {
      VCA_info& vcai = vacks[vca->id()];
      if (vcai.v <= vcv)
      {
        if (vcai.v < vcv)
        {
          vcai.clear();
        }

        delete vcai.vacks[vci];
        vcai.vacks[vci] = vca;
        vcai.v = v;
        return;
      }
    }
  }

  delete vca;
}

inline View View_info::k_max(int k) const
{
  return K_max<View>(k, last_views.data(), node->num_of_replicas(), View_max);
}

View View_info::max_view() const
{
  View ret = k_max(node->f() + 1);
  return ret;
}

View View_info::max_maj_view() const
{
  View ret = k_max(node->num_correct_replicas());
  return ret;
}

void View_info::set_received_vcs(Status* m)
{
  PBFT_ASSERT(m->view() == v, "Invalid argument");

  NV_info& nvi = last_nvs[node->primary(v)];
  if (nvi.view() == v)
  {
    // There is a new-view message for the current view.
    nvi.set_received_vcs(m);
  }
  else
  {
    for (int i = 0; i < node->num_of_replicas(); i++)
    {
      if (last_vcs[i] != 0 && last_vcs[i]->view() == v)
      {
        m->mark_vcs(i);
      }
    }
  }
}

void View_info::set_missing_pps(Status* m)
{
  PBFT_ASSERT(m->view() == view(), "Invalid argument");

  if (last_nvs[node->primary(view())].new_view())
  {
    last_nvs[node->primary(view())].set_missing_pps(m);
  }
}

View_change* View_info::my_view_change(Time& t)
{
  View_change* myvc;
  if (last_vcs[id] == 0)
  {
    myvc = last_nvs[node->primary(v)].view_change(id);
  }
  else
  {
    myvc = last_vcs[id].get();
  }
  if (myvc)
  {
    t = vc_sent;
  }
  return myvc;
}

View_change* View_info::view_change(int rid)
{
  View_change* vc = nullptr;
  if (last_vcs[rid] == 0)
  {
    vc = last_nvs[node->primary(v)].view_change(rid);
  }
  else
  {
    vc = last_vcs[rid].get();
  }

  return vc;
}

New_view* View_info::my_new_view(Time& t)
{
  return last_nvs[id].new_view(t);
}

New_view* View_info::my_new_view()
{
  Time t;
  return last_nvs[id].new_view(t);
}

void View_info::mark_stable(Seqno ls)
{
  last_stable = ls;
  oplog.truncate(last_stable + 1);

  last_nvs[node->primary(v)].mark_stable(ls);
}

void View_info::clear()
{
  oplog.clear(last_stable + 1);

  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    last_vcs[i] = 0;
    last_views[i] = v;
    vacks[i].clear();

    delete my_vacks[i];
    my_vacks[i] = 0;

    last_nvs[i].clear();
  }
  vc_sent = zero_time();
}

bool View_info::shutdown(FILE* o)
{
  int wb = 0, ab = 0;
  bool ret = true;
  for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
  {
    OReq_info& ori = oplog.fetch(i);

    wb += fwrite(&ori.lv, sizeof(View), 1, o);
    wb += fwrite(&ori.v, sizeof(View), 1, o);
    wb += fwrite(&ori.d, sizeof(Digest), 1, o);

    bool hasm = ori.m != 0;
    wb += fwrite(&hasm, sizeof(bool), 1, o);
    ab += 4;

    if (hasm)
    {
      ret &= ori.m->encode(o);
    }
  }

  bool is_complete = has_complete_new_view(v);
  wb += fwrite(&is_complete, sizeof(bool), 1, o);
  ab++;

  return ret & (ab == wb);
}

bool View_info::restart(FILE* in, View rv, Seqno ls, bool corrupt)
{
// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  v = rv;
  last_stable = ls;
  id = node->id();

  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    last_views[i] = v;
  }

  vc_sent = zero_time();

  oplog.clear(last_stable + 1);

  bool ret = !corrupt;
  int rb = 0, ab = 0;
  if (!corrupt)
  {
    for (Seqno i = last_stable + 1; i <= last_stable + max_out; i++)
    {
      OReq_info& ori = oplog.fetch(i);

      rb += fread(&ori.lv, sizeof(View), 1, in);
      rb += fread(&ori.v, sizeof(View), 1, in);
      rb += fread(&ori.d, sizeof(Digest), 1, in);

      bool hasm;
      rb += fread(&hasm, sizeof(bool), 1, in);
      delete ori.m;
      if (hasm)
      {
        ori.m = (Pre_prepare*)new Message;
        ret &= ori.m->decode(in);
      }
      else
      {
        ori.m = 0;
      }

      // Check invariants
      if (hasm)
      {
        ret &= (ori.m->digest() == ori.d) & (ori.m->view() == ori.v) &
          (ori.lv >= ori.v);
      }
      else
      {
        ret &= (ori.lv < ori.v || ori.v == -1);
      }

      if (!ret)
      {
        ori = OReq_info();
        return false;
      }

      ab += 4;
    }
  }

  bool is_complete;
  rb += fread(&is_complete, sizeof(bool), 1, in);
  ab++;
  if (is_complete)
  {
    last_nvs[node->primary(v)].make_complete(v);
  }

  return ret & (ab == rb);
#else
  return true;
#endif
}

bool View_info::enforce_bound(Seqno b, Seqno ks, bool corrupt)
{
  if (corrupt || last_stable > b - max_out)
  {
    last_stable = ks;
    oplog.clear(ks + 1);
    return false;
  }

  for (Seqno i = b; i <= last_stable + max_out; i++)
  {
    OReq_info& ori = oplog.fetch(i);
    if (ori.v >= 0)
    {
      oplog.clear(ks + 1);
      return false;
    }
  }

  return true;
}

void View_info::mark_stale()
{
  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    if (i != id)
    {
      last_vcs[i] = 0;
      if (last_views[i] >= v)
      {
        last_views[i] = v;
      }
    }

    delete my_vacks[i];
    my_vacks[i] = 0;

    View_change* vc = last_nvs[i].mark_stale(id);
    if (vc && vc->view() == view())
    {
      last_vcs[id] = std::unique_ptr<View_change>(vc);
    }
    else
    {
      delete vc;
    }

    vacks[i].clear();
  }
}

void View_info::dump_state(std::ostream& os)
{
  os << "v:" << v << " id:" << id << " last_stable:" << last_stable
     << std::endl;

  os << "last_views:" << std::endl;
  for (int i = 0; i < last_views.size(); i++)
  {
    os << " i:" << i << " view: " << last_views[i];
  }
  os << std::endl;

  os << "last_vcs:" << std::endl;
  for (int i = 0; i < last_vcs.size(); i++)
  {
    os << " i:" << i << " view: ";
    if (last_vcs[i] == nullptr)
    {
      os << "empty";
    }
    else
    {
      os << last_vcs[i]->view()
         << " digest hash:" << last_vcs[i]->digest().hash()
         << " last_stable:" << last_vcs[i]->last_stable()
         << " max_seqno:" << last_vcs[i]->max_seqno();
    }
  }
  os << std::endl;

#ifndef USE_PKEY_VIEW_CHANGES
  os << "my_vacks:" << std::endl;
  for (int i = 0; i < my_vacks.size(); i++)
  {
    os << " i:" << i << " view: ";
    if (my_vacks[i] == nullptr)
    {
      os << "empty";
    }
    else
    {
      os << my_vacks[i]->view()
         << " digest hash:" << my_vacks[i]->vc_digest().hash();
    }
  }
  os << std::endl;

  os << "vacks:" << std::endl;
  for (int i = 0; i < vacks.size(); i++)
  {
    os << " i:" << i << " view: " << vacks[i].v << std::endl;
    for (int j = 0; j < vacks[i].vacks.size(); j++)
    {
      os << " vacks (" << i << "," << j
         << ") vca: " << (void*)vacks[i].vacks[j];
      if (vacks[i].vacks[j] != nullptr)
      {
        os << " digest hash:" << vacks[i].vacks[j]->vc_digest().hash()
           << std::endl;
      }
      else
      {
        os << std::endl;
      }
    }
  }
  os << std::endl;
#endif

  os << "oplog:" << std::endl;
  oplog.dump_state(os);

  os << "last_nvs for primary: " << node->primary(v) << " v: " << v
     << std::endl;
  last_nvs[node->primary(v)].dump_state(os);
  os << std::endl;

  os << "other entries in last_nvs: " << std::endl;
  for (int i = 0; i < last_nvs.size(); i++)
  {
    if (i == node->primary(v))
    {
      continue;
    }

    os << " entry for replica: " << i;
    if (last_nvs[i].is_empty())
    {
      os << " is empty\n";
    }
    else
    {
      os << std::endl;
      last_nvs[i].dump_state(os);
    }
  }
}
