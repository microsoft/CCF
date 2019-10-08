set(PBFT_SRC
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Client.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Replica.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/New_key.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Commit.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Reply.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Digest.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Node.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Request.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Checkpoint.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Pre_prepare.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Req_queue.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Prepare.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Status.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Prepared_cert.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Principal.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Log_allocator.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Meta_data.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Data.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Fetch.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Meta_data_cert.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/State.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/libbyz.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/View_change.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/New_view.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/View_change_ack.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/View_info.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/NV_info.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Rep_info.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Rep_info_exactly_once.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Meta_data_d.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Query_stable.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Reply_stable.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Stable_estimator.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Big_req_table.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/Pre_prepare_info.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/LedgerWriter.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/LedgerReplay.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/LedgerReader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/aes_gcm.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/key_format.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/request_id_gen.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/pbft/libbyz/New_principal.cpp
)

add_definitions(-DSIGN_BATCH)

add_library(libbyz.enclave STATIC ${PBFT_SRC})
target_compile_options(libbyz.enclave PRIVATE
  -nostdinc
  -U__linux__)
target_compile_definitions(libbyz.enclave PRIVATE INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD __USE_SYSTEM_ENDIAN_H__ )
set_property(TARGET libbyz.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(libbyz.enclave PRIVATE SYSTEM ${EVERCRYPT_INC})

add_library(libbyz.host STATIC ${PBFT_SRC})
target_compile_options(libbyz.host PRIVATE -stdlib=libc++)
set_property(TARGET libbyz.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(libbyz.host PRIVATE SYSTEM ${EVERCRYPT_INC})


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
