#pragma once

#if defined(__DragonFly__) && !defined(_KERNEL)
#  include "pal_bsd.h"

namespace snmalloc
{
  /**
   * DragonflyBSD-specific platform abstraction layer.
   *
   * This adds DragonFlyBSD-specific aligned allocation to the BSD
   * implementation.
   */
  class PALDragonfly : public PALBSD<PALDragonfly>
  {
  public:
    /**
     * Bitmap of PalFeatures flags indicating the optional features that this
     * PAL supports.
     *
     * The DragonflyBSD PAL does not currently add any features beyond
     * of those of the BSD Pal.
     * Like FreeBSD, MAP_NORESERVE is implicit.
     * This field is declared explicitly to remind anyone modifying this class
     * to add new features that they should add any required feature flags.
     */
    static constexpr uint64_t pal_features = PALPOSIX::pal_features;
  };
} // namespace snmalloc
#endif
