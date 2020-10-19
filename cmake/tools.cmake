# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

function(add_san name)
  if(SAN)
    target_compile_options(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
    target_link_libraries(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
  endif()
endfunction()

separate_arguments(
  COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)
separate_arguments(
  COVERAGE_LINK UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)

function(enable_coverage name)
  if(COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
  endif()
endfunction()
