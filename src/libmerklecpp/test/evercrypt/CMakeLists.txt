project(evercrypt LANGUAGES C ASM)

option(PROFILE "enable profiling" OFF)
option(EVERCRYPT "enable comparison with EverCrypt Merkle trees" OFF)

if(EVERCRYPT)
  if(NOT (DEFINED $ENV{EVERCRYPT_DIR}))
    set(EVERCRYPT_DIR ../../../../3rdparty/hacl-star/evercrypt)
  endif()

  set(EVERCRYPT_INC ${EVERCRYPT_DIR} ${EVERCRYPT_DIR}/kremlin
                    ${EVERCRYPT_DIR}/kremlin/kremlib
  )

  file(GLOB EVEREST_SRC "${EVERCRYPT_DIR}/*.c"
       "${EVERCRYPT_DIR}/*-x86_64-linux.S"
  )

  add_library(evercrypt STATIC ${EVEREST_SRC})
  target_include_directories(evercrypt PRIVATE ${EVERCRYPT_INC})

  if(PROFILE)
    target_compile_options(evercrypt PRIVATE -g -pg)
    target_link_options(evercrypt PRIVATE -g -pg)
  endif()
endif()
