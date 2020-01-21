#pragma once

#ifdef EXPORT_THREAD_LOCALS
#  define VISIBILITY_SPEC __attribute__((visibility("default")))
#else
#  define VISIBILITY_SPEC __attribute__((visibility("hidden")))
#endif
