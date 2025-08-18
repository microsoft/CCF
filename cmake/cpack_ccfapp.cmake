# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(${CCF_DIR}/cmake/cpack_versions_pin.cmake)

set(CCF_RPM_DEPENDENCIES "openssl >= ${OPENSSL_MINIMAL_VERSION}")
set(CCF_RPM_DEPENDENCIES
    "${CCF_RPM_DEPENDENCIES}, nghttp2 >= ${NGHTTP2_MINIMAL_VERSION}"
)
set(CCF_RPM_DEPENDENCIES
    "${CCF_RPM_DEPENDENCIES}, libuv >= ${LIBUV_MINIMAL_VERSION}"
)
set(CCF_RPM_DEPENDENCIES
    "${CCF_RPM_DEPENDENCIES}, curl >= ${CURL_MINIMAL_VERSION}"
)
set(CCF_RPM_DEPENDENCIES
    "${CCF_RPM_DEPENDENCIES}, libcxxabi >= ${CLANG_AND_LIBCXXABI_MINIMAL_VERSION}"
)

set(CPACK_CCF_RUNTIME_REQUIRES "${CCF_RPM_DEPENDENCIES}")
