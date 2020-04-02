// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "state.h"

#include "data.h"
#include "ds/logger.h"
#include "fetch.h"
#include "meta_data.h"
#include "meta_data_cert.h"
#include "meta_data_d.h"
#include "pbft_assert.h"
#include "replica.h"
#include "statistics.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

//
// The memory managed by the state abstraction is partitioned into
// blocks.
//
struct Block
{
  char data[Block_size];

  inline Block() {}

  inline Block(Block const& other)
  {
    memcpy(data, other.data, Block_size);
  }

  inline Block& operator=(Block const& other)
  {
    if (this == &other)
    {
      return *this;
    }

    memcpy(data, other.data, Block_size);
    return *this;
  }

  inline Block& operator=(char const* other)
  {
    if (this->data == other)
    {
      return *this;
    }

    memcpy(data, other, Block_size);
    return *this;
  }
};

// Blocks are grouped into partitions that form a hierarchy.
// Part contains information about one such partition.
struct Part
{
  Seqno lm; // Sequence number of last checkpoint that modified partition
  Digest d; // Digest of partition

  Part()
  {
    lm = 0;
  }
};

// Information about stale partitions being fetched.
struct FPart
{
  FPart(
    size_t index,
    Seqno lu, // Latest checkpoint seqno for which partition is up-to-date
    Seqno lm, // Sequence number of last checkpoint that modified partition
    Seqno c, // Sequence number of checkpoint being fetched
    Digest d) // Digest of checkpoint being fetched
    :
    index(index),
    lu(lu),
    lm(lm),
    c(c),
    d(d)
  {}

  size_t index;
  Seqno lu; // Latest checkpoint seqno for which partition is up-to-date
  Seqno lm; // Sequence number of last checkpoint that modified partition
  Seqno c; // Sequence number of checkpoint being fetched
  Digest d; // Digest of checkpoint being fetched
};

class FPartQueue : public std::vector<FPart>
{};

// Information about partitions whose digest is being checked.
struct CPart
{
  CPart(size_t index, int level) : index(index), level(level) {}

  size_t index;
  int level;
};
class CPartQueue : public std::vector<CPart>
{};

// Copy of leaf partition (used in checkpoint records)
struct BlockCopy : public Part
{
  Block data; // Copy of data at the time the checkpoint was taken

  BlockCopy() : Part() {}
};

// Key for partition map in checkpoint records

PartKey::PartKey() {}
PartKey::PartKey(size_t l, size_t i) : level(l), index(i) {}

void PartKey::operator=(PartKey const& x)
{
  level = x.level;
  index = x.index;
}

size_t PartKey::hash() const
{
  return ((size_t)level) ^ ((size_t)index);
}

bool PartKey::operator==(PartKey const& x) const
{
  return (level == x.level) && (index == x.index);
}

Checkpoint_rec::Checkpoint_rec() : parts(256) {}

Checkpoint_rec::~Checkpoint_rec()
{
  clear();
}

void Checkpoint_rec::append(int l, size_t i, Part* p)
{
  PBFT_ASSERT(parts.find(PartKey(l, i)) == parts.end(), "Invalid state");
  parts.insert({PartKey(l, i), p});
}

void Checkpoint_rec::appendr(int l, size_t i, Part* p)
{
  if (parts.find(PartKey(l, i)) != parts.end())
  {
    return;
  }

  append(l, i, p);
}

Part* Checkpoint_rec::fetch(int l, size_t i)
{
  auto it = parts.find(PartKey(l, i));
  if (it != parts.end())
  {
    return it->second;
  }
  return 0;
}

bool Checkpoint_rec::is_empty()
{
  return sd.is_zero();
}

bool Checkpoint_rec::is_complete()
{
  return false;
}

int Checkpoint_rec::num_entries() const
{
  return parts.size();
}

void Checkpoint_rec::dump_state(std::ostream& os)
{
  os << "digest hash: " << sd.hash() << " num_parts:" << parts.size()
     << std::endl;
}

void Checkpoint_rec::print()
{
  LOG_INFO << "Checkpoint record: " << parts.size() << " blocks" << std::endl;
  for (auto const& p : parts)
  {
    LOG_INFO << "Block: level= " << p.first.level << " index= " << p.first.index
             << std::endl;
    LOG_INFO << "last mod= " << p.second->lm << std::endl;
    p.second->d.print();
  }
}

void Checkpoint_rec::clear()
{
  if (!is_empty())
  {
    auto it = parts.begin();
    while (it != parts.end())
    {
      if (it->first.level == PLevels - 1)
      {
        delete ((BlockCopy*)it->second);
      }
      else
      {
        delete it->second;
      }
      it = parts.erase(it);
    }
    sd.zero();
  }
}

bool Checkpoint_rec::Iter::get(int& level, size_t& index, Part*& p)
{
  // Effects: Modifies "level", "index" and "p" to contain
  // information for the next partition in "r" and returns
  // true. Unless there are no more partitions in "r" in which case
  // it returns false.

  if (it != end)
  {
    PartKey k = it->first;
    level = k.level;
    index = k.index;
    p = it->second;
    it++;
    return true;
  }
  return false;
}

template class Log<Checkpoint_rec>;

//
// State methods:
//
State::State(
  Replica* rep,
  char* memory,
  size_t num_bytes,
  size_t num_of_replicas,
  size_t f) :
  replica(rep),
  mem((Block*)memory),
  nb(num_bytes / Block_size),
  end_mem(memory + num_bytes),
  cowb(nb),
  checkpoint_log(max_out * 2, 0),
  lc(0),
  last_fetch_t(0)
{
  for (int i = 0; i < PLevels; i++)
  {
    ptree[i] =
      std::make_unique<Part[]>((i != PLevels - 1) ? PLevelSize[i] : nb);
    stalep[i] = std::make_unique<FPartQueue>();
  }

  for (int i = 0; i < PLevels; i++)
  {
    stree[i] = std::make_unique<Digest[]>(PLevelSize[i]);
  }

  fetching = false;
  cert = std::make_unique<Meta_data_cert>(num_of_replicas, f);
  lreplier = 0;

  to_check = std::make_unique<CPartQueue>();
  checking = false;
  refetch_level = 0;
}

State::~State() {}

void State::cow_single(int i)
{
  BlockCopy* bcp;
  PBFT_ASSERT(i >= 0 && i < nb, "Invalid argument");

  INCR_OP(num_cows);
  // Append a copy of the block to the last checkpoint
  Part& p = ptree[PLevels - 1][i];
  bcp = new BlockCopy;
  bcp->data = mem[i];
  bcp->lm = p.lm;
  bcp->d = p.d;

  checkpoint_log.fetch(lc).append(PLevels - 1, i, bcp);
  cowb.set(i);
}

void State::cow(char* m, int size)
{
  if (size > 0 && m >= (char*)mem && m + size <= end_mem)
  {
    // Find index of low and high block
    int low = (m - (char*)mem) / Block_size;
    int high = (m + size - 1 - (char*)mem) / Block_size;

    for (int bindex = low; bindex <= high; bindex++)
    {
      // If cow bit is set do not perform copy.
      if (cowb.test(bindex))
      {
        continue;
      }
      cow_single(bindex);
    }
  }
}

void State::digest(Digest& d, size_t i, Seqno lm, char* data, int size)
{
  // Compute digest for partition p:
  // Digest((data,size) | last modification seqno | i)
  Digest::Context ctx;
  d.update(ctx, data, size);
  struct
  {
    Seqno lm;
    size_t i;
  } contiguous_args = {lm, i};
  d.update_last(ctx, (char*)&contiguous_args, sizeof(Seqno) + sizeof(size_t));
  d.finalize(ctx);
}

inline int State::digest(Digest& d, int l, size_t i)
{
  char* data;
  int size;

  if (l == PLevels - 1)
  {
    PBFT_ASSERT(i >= 0 && i < nb, "Invalid argument");
    data = mem[i].data;
    size = Block_size;
  }
  else
  {
    data = stree[l + 1][i * PChildren].digest();
    size = PChildren * sizeof(Digest);
  }

  digest(d, i, ptree[l][i].lm, data, size);
  stree[l][i] = d;

  return size;
}

void State::compute_full_digest()
{
#ifndef INSIDE_ENCLAVE
  Cycle_counter cc;
  cc.start();
#endif
  int np = nb;
  for (int l = PLevels - 1; l > 0; l--)
  {
    for (int i = 0; i < np; i++)
    {
      Digest& d = ptree[l][i].d;
      digest(d, l, i);
    }
    np = (np + PSize[l] - 1) / PSize[l];
  }

  Digest& d = ptree[0][0].d;
  digest(d, 0, 0);

  cowb.clear();
  checkpoint_log.fetch(0).clear();
  checkpoint(0);
#ifndef INSIDE_ENCLAVE
  cc.stop();
  LOG_INFO << "Compute full digest elapsed " << cc.elapsed() << std::endl;
#endif

  d.print();
}

void State::update_ptree(Seqno n)
{
  Bitmap* mods[PLevels];
  for (int l = 0; l < PLevels - 1; l++)
  {
    mods[l] = new Bitmap(PLevelSize[l]);
  }
  mods[PLevels - 1] = &cowb;

  Checkpoint_rec& cr = checkpoint_log.fetch(lc);

  for (int l = PLevels - 1; l > 0; l--)
  {
    Bitmap::Iter iter(mods[l]);
    size_t i;
    while (iter.get(i))
    {
      Part& p = ptree[l][i];
      if (l < PLevels - 1)
      {
        // Append a copy of the partition to the last checkpoint
        Part* np = new Part;
        np->lm = p.lm;
        np->d = p.d;
        cr.append(l, i, np);
      }

      // Update partition information
      p.lm = n;
      digest(p.d, l, i);

      // Mark parent modified
      mods[l - 1]->set(i / PSize[l]);
    }
  }

  if (mods[0]->test(0))
  {
    Part& p = ptree[0][0];

    // Append a copy of the root partition to the last checkpoint
    Part* np = new Part;
    np->lm = p.lm;
    np->d = p.d;
    cr.append(0, 0, np);

    // Update root partition.
    p.lm = n;
    digest(p.d, 0, 0);
  }

  for (int l = 0; l < PLevels - 1; l++)
  {
    delete mods[l];
  }
}

void State::checkpoint(Seqno seqno)
{
  INCR_OP(num_ckpts);

  update_ptree(seqno);

  lc = seqno;
  Checkpoint_rec& nr = checkpoint_log.fetch(seqno);
  nr.sd = ptree[0][0].d;

  cowb.clear();
}

Seqno State::rollback(Seqno last_executed)
{
  PBFT_ASSERT(lc >= 0 && !fetching, "Invalid state");

  INCR_OP(num_rollbacks);

  LOG_INFO << "Rolling back to checkpoint before " << last_executed << "\n";

  while (1)
  {
    // Roll back to last checkpoint.
    Checkpoint_rec& cr = checkpoint_log.fetch(lc);

    if (!cr.is_empty())
    {
      Checkpoint_rec::Iter iter(&cr);
      size_t index;
      int level;
      Part* part;

      while (iter.get(level, index, part))
      {
        if (level == PLevels - 1)
        {
          BlockCopy* b = (BlockCopy*)part;
          mem[index] = b->data;
        }
        ptree[level][index].lm = part->lm;
        ptree[level][index].d = part->d;
      }

      PBFT_ASSERT(ptree[0][0].d == cr.sd, "Invalid state");
      cr.clear();
      cowb.clear();

      if (lc <= last_executed)
      {
        // set up checkpoint record as if we had just computed the
        // checkpoint
        cr.sd = ptree[0][0].d;
        break;
      }
    }

    lc--;
  }

  LOG_DEBUG << "Rolled back to  " << lc << "\n";

  return lc;
}

bool State::digest(Seqno n, Digest& d)
{
  if (!checkpoint_log.within_range(n))
  {
    return false;
  }

  Checkpoint_rec& rec = checkpoint_log.fetch(n);
  if (rec.sd.is_zero())
  {
    return false;
  }

  d = rec.sd;
  return true;
}

void State::discard_checkpoints(Seqno seqno, Seqno le)
{
  if (seqno > lc && le >= seqno)
  {
    checkpoint(seqno);
  }

  checkpoint_log.truncate(seqno);
}

//
// Fetching missing state:
//
char* State::get_data(Seqno c, int i)
{
  PBFT_ASSERT(
    checkpoint_log.within_range(c) && i >= 0 && i < nb, "Invalid argument");

  if (ptree[PLevels - 1][i].lm <= c && !cowb.test(i))
  {
    return mem[i].data;
  }

  for (; c <= lc; c += checkpoint_interval)
  {
    Checkpoint_rec& r = checkpoint_log.fetch(c);

    // Skip checkpoint seqno if record has no state.
    if (r.sd.is_zero())
    {
      continue;
    }

    Part* p = r.fetch(PLevels - 1, i);
    if (p)
    {
      return ((BlockCopy*)p)->data.data;
    }
  }

  return nullptr;
}

Part& State::get_meta_data(Seqno c, int l, int i)
{
  PBFT_ASSERT(checkpoint_log.within_range(c), "Invalid argument");

  Part& p = ptree[l][i];
  if (p.lm <= c)
  {
    return p;
  }

  for (; c <= lc; c += checkpoint_interval)
  {
    Checkpoint_rec& r = checkpoint_log.fetch(c);

    // Skip checkpoint seqno if record has no state.
    if (r.sd.is_zero())
    {
      continue;
    }

    Part* p = r.fetch(l, i);
    if (p)
    {
      return *p;
    }
  }
  // PBFT_ASSERT(0, "Invalid state");
  return p; // never reached
}

void State::start_fetch(Seqno le, Seqno c, Digest* cd, bool stable)
{
  LOG_DEBUG << "Starting fetch le: " << le << "c:" << c << std::endl;
  if (!fetching)
  {
    INCR_OP(num_fetches);

    fetching = true;
    keep_ckpts = false;
    lreplier = rand() % pbft::GlobalState::get_replica().num_of_replicas();

    // Update partition information to reflect last modification
    // rather than last checkpointed modification.
    if (lc >= 0 && lc < le && le >= checkpoint_log.head_seqno())
    {
      checkpoint(le);
    }

    // Initialize data structures.
    cert->clear();
    for (int i = 0; i < PLevels; i++)
    {
      stalep[i]->clear();
    }

    // Start by fetching root information.
    flevel = 0;
    stalep[0]->emplace_back(
      0,
      ((refetch_level == PLevels) ? -1 : lc),
      ptree[0][0].lm,
      c,
      ((cd != nullptr) ? *cd : Digest()));
    send_fetch(true);
  }
}

void State::send_fetch(bool change_replier)
{
  last_fetch_t = ITimer::current_time();
  Request_id rid = pbft::GlobalState::get_replica().new_rid();
  pbft::GlobalState::get_replica().principal()->set_last_fetch_rid(rid);

  PBFT_ASSERT(stalep[flevel]->size() > 0, "Invalid state");
  FPart& p = stalep[flevel]->back();

  int replier = -1;
  if (p.c >= 0)
  {
    // Select a replier.
    if (change_replier)
    {
      do
      {
        lreplier =
          (lreplier + 1) % pbft::GlobalState::get_replica().num_of_replicas();
      } while (lreplier == pbft::GlobalState::get_replica().id());
    }
    replier = lreplier;
  }

#ifdef PRINT_STATS
  if (checking && ptree[flevel][p.index].lm > check_start)
  {
    if (flevel == PLevels - 1)
    {
      INCR_OP(refetched);
    }
    else
    {
      INCR_OP(meta_data_refetched);
    }
  }
#endif // PRINT_STATS

  // Send fetch to all.
  Fetch f(rid, p.lu, flevel, p.index, p.c, replier);
  pbft::GlobalState::get_replica().send(&f, Node::All_replicas);
  LOG_TRACE << "Sending fetch message: rid=" << rid << " lu=" << p.lu << " ("
            << flevel << "," << p.index << ") c=" << p.c << " rep=" << replier
            << std::endl;

  if (!cert->has_mine())
  {
    Seqno ls = checkpoint_log.head_seqno();
    if (!checkpoint_log.fetch(ls).is_empty() && p.c <= lc)
    {
      // Add my Meta_data_d message to the certificate
      Meta_data_d* mdd = new Meta_data_d(rid, flevel, p.index, ls);

      for (Seqno n = ls; n <= lc; n += checkpoint_interval)
      {
        if (checkpoint_log.fetch(n).sd.is_zero())
        {
          continue;
        }
        Part& q = get_meta_data(n, flevel, p.index);
        mdd->add_digest(n, q.d);
      }

      cert->add(mdd, true);
    }
  }
}

bool State::handle(Fetch* m, Seqno ls)
{
  std::shared_ptr<Principal> pi =
    pbft::GlobalState::get_replica().get_principal(m->id());
  if (pi == nullptr)
  {
    delete m;
    return false;
  }

  if (fetching)
  {
    // ignore fetch requests while we are fetching state
    delete m;
    return true;
  }

  int l = m->level();
  int i = m->index();

  if (pi->last_fetch_rid() < m->request_id() && (l < PLevels - 1 || i < nb))
  {
    Seqno rc = m->checkpoint();

    LOG_TRACE << "Receive fetch ls=" << ls << " rc= " << rc
              << " lu=" << m->last_uptodate() << " lm=" << ptree[l][i].lm
              << std::endl;

    if (rc >= 0 && m->replier() == pbft::GlobalState::get_replica().id())
    {
      Seqno chosen = -1;
      if (
        checkpoint_log.within_range(rc) && !checkpoint_log.fetch(rc).is_empty())
      {
        // Replica has the requested checkpoint
        chosen = rc;
      }
      else if (
        lc >= rc && ptree[l][i].lm <= rc &&
        !checkpoint_log.fetch(lc).is_empty())
      {
        // Replica's last checkpoint has same value as requested
        // checkpoint for this partition
        chosen = lc;
      }

      if (chosen >= 0)
      {
        if (l == PLevels - 1)
        {
          // Send data
          Part& p = get_meta_data(chosen, l, i);
          char* data = get_data(chosen, i);
          if (data != nullptr)
          {
            Data d(i, p.lm, data);
            pbft::GlobalState::get_replica().send(&d, m->id());
            LOG_TRACE << "Sending data i=" << i << " lm=" << p.lm << std::endl;
          }
        }
        else
        {
          // Send meta-data
          Part& p = get_meta_data(chosen, l, i);
          Meta_data md(m->request_id(), l, i, chosen, p.lm, p.d);
          Seqno thr = m->last_uptodate();

          l++;
          int j = i * PSize[l];
          int max = j + PSize[l];
          if (l == PLevels - 1 && max > nb)
          {
            max = nb;
          }
          for (; j < max; j++)
          {
            Part& q = get_meta_data(chosen, l, j);
            if (q.lm > thr)
            {
              md.add_sub_part(j, q.d);
            }
          }
          pbft::GlobalState::get_replica().send(&md, m->id());
          LOG_TRACE << "Sending meta-data l=" << l - 1 << " i=" << i
                    << " lm=" << p.lm << std::endl;
        }
        delete m;
        return true;
      }
    }

    if (ls > rc && ls >= m->last_uptodate() && ptree[l][i].lm > rc)
    {
      // Send meta-data-d
      Meta_data_d mdd(m->request_id(), l, i, ls);

      Seqno n =
        (checkpoint_log.fetch(ls).is_empty()) ? ls + checkpoint_interval : ls;
      for (; n <= lc; n += checkpoint_interval)
      {
        Part& p = get_meta_data(n, l, i);
        LOG_TRACE << "Adding digest meta-data-d l=" << l << " i=" << i
                  << " n=" << n << " digest[0]=" << p.d.hash() << std::endl;
        mdd.add_digest(n, p.d);
      }

      if (mdd.num_digests() > 0)
      {
        mdd.authenticate(pi.get());
        LOG_TRACE << "Sending meta-data-d l=" << l << " i=" << i << std::endl;
        pbft::GlobalState::get_replica().send(&mdd, m->id());
      }
    }
  }

  delete m;
  return true;
}

void State::handle(Data* m)
{
  INCR_OP(num_fetched);

  int l = PLevels - 1;
  if (fetching && flevel == l)
  {
    FPart& wp = stalep[l]->back();
    size_t i = wp.index;

    if (m->index() == i)
    {
      Digest d;
      digest(d, i, m->last_mod(), m->data(), Block_size);
      if (wp.c >= 0 && wp.d == d)
      {
        INCR_OP(num_fetched_a);

        Part& p = ptree[l][i];

        if (keep_ckpts && !cowb.test(i))
        {
          // Append a copy of p to the last checkpoint
          BlockCopy* bcp;
          bcp = new BlockCopy;
          bcp->data = mem[i];
          bcp->lm = p.lm;
          bcp->d = p.d;

          checkpoint_log.fetch(lc).append(l, i, bcp);
        }

        p.d = wp.d;
        stree[l][i] = p.d;
        p.lm = m->last_mod();

        // Set data to the right value. Note that we set the
        // most current value of the data.
        cowb.set(i);
        mem[i] = m->data();

        FPart& pwp = stalep[l - 1]->back();
        PBFT_ASSERT(
          pwp.index == i / PSize[l], "Parent is not first at level l-1 queue");
        if (p.lm > pwp.lm)
        {
          pwp.lm = p.lm;
        }

        cert->clear();
        stalep[l]->pop_back();

        if (stalep[l]->size() == 0)
        {
          done_with_level();
          delete m;
          return;
        }
      }

      send_fetch();
    }
  }
  delete m;
}

bool State::check_digest(Digest& d, Meta_data* m)
{
  PBFT_ASSERT(m->level() < PLevels - 1, "Invalid argument");

  int l = m->level();
  int i = m->index();
  std::vector<Digest> to_undo;
  to_undo.resize(m->num_sparts());
  Meta_data::Sub_parts_iter miter(m);
  Digest dp;
  size_t ip;
  while (miter.get(ip, dp))
  {
    if (ip >= nb && l + 1 == PLevels - 1)
    {
      break;
    }

    if (!dp.is_zero())
    {
      // temporarily put the new digest in stree
      to_undo.emplace_back(stree[l + 1][ip]);
      stree[l + 1][ip] = dp;
    }
  }

  digest(
    dp,
    i,
    m->last_mod(),
    stree[l + 1][i * PChildren].digest(),
    PChildren * sizeof(Digest));

  bool match = (d == dp);
  if (!match)
  {
    LOG_INFO << "Digest does not match l=" << l << ", i=" << i
             << " d=" << d.hash() << " dp=" << dp.hash() << std::endl;
  }

  // undo changes to stree
  Meta_data::Sub_parts_iter miter1(m);
  int undo_index = 0;
  while (miter1.get(ip, dp))
  {
    if (ip >= nb && l + 1 == PLevels - 1)
    {
      break;
    }

    if (!dp.is_zero())
    {
      stree[l + 1][ip] = to_undo[undo_index++];
    }
  }

  return match;
}

void State::handle(Meta_data* m)
{
  INCR_OP(meta_data_fetched);
  INCR_CNT(meta_data_bytes, m->size());

  Request_id crid =
    pbft::GlobalState::get_replica().principal()->last_fetch_rid();
  LOG_TRACE << "Got meta_data index " << m->index() << " from " << m->id()
            << " rid=" << m->request_id() << " crid=" << crid << std::endl;
  if (
    fetching && flevel < PLevels - 1 && m->request_id() == crid &&
    flevel == m->level())
  {
    FPart& wp = stalep[flevel]->back();

    if (wp.index == m->index() && wp.c >= 0 && m->digest() == wp.d)
    {
      // Requested a specific digest that matches the one in m
      if (m->verify() && check_digest(wp.d, m))
      {
        INCR_OP(meta_data_fetched_a);

        // Meta-data was fetched successfully.
        LOG_TRACE << "Accepted meta_data from " << m->id() << " (" << flevel
                  << "," << wp.index << ")" << std::endl;

        wp.lm = m->last_mod();

        // Queue out-of-date subpartitions for fetching, and if
        // checking, queue up-to-date partitions for checking.
        flevel++;
        PBFT_ASSERT(stalep[flevel]->size() == 0, "Invalid state");

        Meta_data::Sub_parts_iter iter(m);
        Digest d;
        size_t index;
        while (iter.get(index, d))
        {
          if (flevel == PLevels - 1 && index >= nb)
          {
            break;
          }

          Part& p = ptree[flevel][index];

          if (d.is_zero() || p.d == d)
          {
            // Sub-partition is up-to-date
            if (refetch_level == PLevels && p.lm <= check_start)
            {
              to_check->emplace_back(index, flevel);
            }
          }
          else
          {
            // Sub-partition is out-of-date
            stalep[flevel]->emplace_back(index, wp.lu, p.lm, wp.c, d);
          }
        }

        cert->clear();

        if (stalep[flevel]->size() == 0)
        {
          done_with_level();
        }
        else
        {
          send_fetch();
        }
      }
    }
  }

  delete m;
}

void State::handle(Meta_data_d* m)
{
  INCR_OP(meta_datad_fetched);
  INCR_CNT(meta_datad_bytes, m->size());

  LOG_TRACE << "Got meta_data_d from " << m->id() << "index" << m->index()
            << std::endl;
  Request_id crid =
    pbft::GlobalState::get_replica().principal()->last_fetch_rid();
  if (fetching && m->request_id() == crid && flevel == m->level())
  {
    FPart& wp = stalep[flevel]->back();

    if (
      wp.index == m->index() && m->last_stable() >= lc &&
      m->last_stable() >= wp.lu)
    {
      INCR_OP(meta_datad_fetched_a);

      // Insert message in certificate for working partition
      Digest cd;
      Seqno cc;
      if (cert->add(m))
      {
        LOG_TRACE << "Got meta_data_d from " << m->id() << "index "
                  << m->index() << "and ADDED to cert" << std::endl;
        if (cert->last_stable() > lc)
        {
          keep_ckpts = false;
        }

        if (cert->cvalue(cc, cd))
        {
          // Certificate is now complete.
          wp.c = cc;
          wp.d = cd;
          LOG_TRACE << "Complete meta_data_d cert (" << flevel << ","
                    << wp.index << ")" << std::endl;

          cert->clear();

          PBFT_ASSERT(flevel != PLevels - 1 || wp.index < nb, "Invalid state");
          if (cd == ptree[flevel][wp.index].d)
          {
            // State is up-to-date
            if (
              refetch_level == PLevels &&
              ptree[flevel][wp.index].lm <= check_start)
            {
              to_check->emplace_back(flevel, wp.index);
            }

            if (flevel > 0)
            {
              stalep[flevel]->pop_back();
              if (stalep[flevel]->size() == 0)
              {
                done_with_level();
              }
            }
            else
            {
              flevel++;
              done_with_level();
            }
            return;
          }
          send_fetch(true);
        }
      }

      return;
    }
  }

  delete m;
}

void State::done_with_level()
{
  PBFT_ASSERT(stalep[flevel]->size() == 0, "Invalid state");
  PBFT_ASSERT(flevel > 0, "Invalid state");

  flevel--;
  FPart& wp = stalep[flevel]->back();
  int i = wp.index;
  int l = flevel;

  wp.lu = wp.c;
  PBFT_ASSERT(wp.c != -1, "Invalid state");

  if (wp.lu >= wp.lm)
  {
    // partition is consistent: update ptree and stree, and remove it
    // from stalep
    Part& p = ptree[l][i];

    if (keep_ckpts)
    {
      // Append a copy of p to the last checkpoint
      Part* np = new Part;
      np->lm = p.lm;
      np->d = p.d;
      checkpoint_log.fetch(lc).appendr(l, i, np);
    }

    p.lm = wp.lm;
    p.d = wp.d;
    stree[l][i] = p.d;

    if (l > 0)
    {
      FPart& pwp = stalep[l - 1]->back();
      PBFT_ASSERT(
        pwp.index == i / PSize[l], "Parent is not first at level l-1 queue");
      if (p.lm > pwp.lm)
      {
        pwp.lm = p.lm;
      }
    }

    if (l == 0)
    {
      // Completed fetch
      fetching = false;
      if (checking && to_check->size() == 0)
      {
        checking = false;
      }

      if (keep_ckpts && lc % checkpoint_interval != 0)
      {
        // Move parts from this checkpoint to previous one
        Seqno prev = lc / checkpoint_interval * checkpoint_interval;
        if (
          checkpoint_log.within_range(prev) &&
          !checkpoint_log.fetch(prev).is_empty())
        {
          Checkpoint_rec& pr = checkpoint_log.fetch(prev);
          Checkpoint_rec& cr = checkpoint_log.fetch(lc);
          Checkpoint_rec::Iter g(&cr);
          int pl;
          size_t pi;
          Part* p;
          while (g.get(pl, pi, p))
          {
            pr.appendr(pl, pi, p);
          }
        }
      }

      // Create checkpoint record for current state
      PBFT_ASSERT(lc <= wp.lu, "Invalid state");
      lc = wp.lu;

      if (!checkpoint_log.within_range(lc))
      {
        checkpoint_log.truncate(lc - max_out);
      }

      Checkpoint_rec& nr = checkpoint_log.fetch(lc);
      nr.sd = ptree[0][0].d;
      cowb.clear();
      stalep[l]->pop_back();
      cert->clear();

      // If checking state, stop adding partitions to to_check because
      // all partitions that had to be checked have already been
      // queued.
      refetch_level = 0;
      poll_cnt = 16;

      pbft::GlobalState::get_replica().new_state(lc);

      return;
    }
    else
    {
      stalep[l]->pop_back();
      if (stalep[l]->size() == 0)
      {
        done_with_level();
        return;
      }

      // Moving to a sibling.
      if (flevel <= refetch_level)
      {
        refetch_level = PLevels;
      }
    }
  }
  else
  {
    // Partition is inconsistent
    if (flevel < refetch_level)
    {
      refetch_level = flevel;
    }
  }

  send_fetch();
}

//
// State checking:
//
void State::start_check(Seqno le)
{
  checking = true;
  refetch_level = PLevels;
  lchecked = -1;
  check_start = lc;
  corrupt = false;
  poll_cnt = 16;

  start_fetch(le);
}

inline bool State::check_data(int i)
{
  PBFT_ASSERT(i < nb, "Invalid state");

  Part& p = ptree[PLevels - 1][i];
  Digest d;
  digest(d, PLevels - 1, i);

  return d == p.d;
}

void State::check_state()
{
  int count = 1;
  while (to_check->size() > 0)
  {
    const CPart& cp = to_check->at(0);
    int min = cp.index * PBlocks[cp.level];
    int max = min + PBlocks[cp.level];
    if (max > nb)
    {
      max = nb;
    }

    if (lchecked < min || lchecked >= max)
    {
      lchecked = min;
    }

    while (lchecked < max)
    {
      if (
        count % poll_cnt == 0 &&
        pbft::GlobalState::get_replica().has_messages(0))
      {
        return;
      }

      Part& p = ptree[PLevels - 1][lchecked];

      if (p.lm > check_start || check_data(lchecked))
      {
        // Block was fetched after check started or has correct digest.
        INCR_OP(num_checked);
        count++;
        lchecked++;
      }
      else
      {
        corrupt = true;
        PBFT_FAIL("Replica's state is corrupt. Should not happen yet");
      }
    }

    to_check->at(0) = to_check->back();
    to_check->pop_back();
  }

  if (!fetching)
  {
    checking = false;
    refetch_level = 0;
    pbft::GlobalState::get_replica().try_end_recovery();
  }
}

void State::mark_stale()
{
  cert->clear();
}

bool State::enforce_bound(Seqno b, Seqno ks, bool corrupt)
{
  bool ret = true;
  for (int i = 0; i < PLevels; i++)
  {
    int psize = (i != PLevels - 1) ? PLevelSize[i] : nb;
    for (int j = 0; j < psize; j++)
    {
      if (ptree[i][j].lm >= b)
      {
        ret = false;
        ptree[i][j].lm = -1;
      }
    }
  }

  if (!ret || corrupt || checkpoint_log.head_seqno() >= b)
  {
    lc = -1;
    checkpoint_log.clear(ks);
    return false;
  }

  return true;
}

void State::dump_state(std::ostream& os)
{
  os << "fetching: " << fetching << " lc: " << lc
     << " checkpoint_log:" << std::endl;
  checkpoint_log.dump_state(os);
}
