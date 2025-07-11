set(SUBMITTER_DIR ${CCF_DIR}/tests/perf-system/submitter)

add_executable(
  submit ${SUBMITTER_DIR}/submit.cpp ${SUBMITTER_DIR}/handle_arguments.h
         ${SUBMITTER_DIR}/parquet_data.h
)
target_compile_definitions(submit PRIVATE CCF_LOGGER_NO_DEPRECATE)

target_link_libraries(submit PRIVATE http_parser ccfcrypto arrow parquet)

install(TARGETS submit DESTINATION bin)
