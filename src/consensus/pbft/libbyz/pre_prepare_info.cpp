// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "pre_prepare_info.h"

#include "pre_prepare.h"
#include "replica.h"

Pre_prepare_info::~Pre_prepare_info()
{
  delete pp;
}

void Pre_prepare_info::add(Pre_prepare* p)
{
  PBFT_ASSERT(pp == 0, "Invalid state");
  pp = p;
  mreqs = p->num_big_reqs();
  mrmap.reset();
  Big_req_table* brt = pbft::GlobalState::get_replica().big_reqs();

  for (int i = 0; i < p->num_big_reqs(); i++)
  {
    if (brt->add_pre_prepare(p->big_req_digest(i), i, p->seqno(), p->view()))
    {
      mreqs--;
      mrmap.set(i);
    }
  }
}

void Pre_prepare_info::add(Digest& rd, int i)
{
  if (pp && i >= 0 && i < pp->num_big_reqs() && pp->big_req_digest(i) == rd)
  {
    mreqs--;
    mrmap.set(i);
  }
}

void Pre_prepare_info::dump_state(std::ostream& os)
{
  os << "pp: " << (void*)pp;
  if (pp != nullptr)
  {
    os << " num_big_reqs: " << pp->num_big_reqs();
  }
  os << " mreqs: " << mreqs << " mrmap: " << mrmap << std::endl;
}

Pre_prepare_info::BRS_iter::BRS_iter(Pre_prepare_info const* p, const BR_map& m)
{
  ppi = p;
  mrmap = m;
  next = 0;
}

bool Pre_prepare_info::BRS_iter::get(Request*& r)
{
  Pre_prepare* pp = ppi->pp;
  while (pp && next < pp->num_big_reqs())
  {
    if (!mrmap.test(next) & ppi->mrmap.test(next))
    {
      r = pbft::GlobalState::get_replica().big_reqs()->lookup(
        pp->big_req_digest(next));
      PBFT_ASSERT(r != 0, "Invalid state");
      next++;
      return true;
    }
    next++;
  }
  return false;
}
