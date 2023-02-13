# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

function(add_san name)
  # CCF_PROJECT is defined when building CCF itself, but not when this function
  # is used by downstream applications.
  if(CCF_PROJECT)
    set(suppressions_file
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/san_common.suppressions>$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/bin/san_common.suppressions>
    )
  else()
    set(suppressions_file ${CCF_DIR}/bin/san_common.suppressions)
  endif()
  if(TSAN)
    target_compile_options(
      ${name} PRIVATE -fsanitize=thread
                      -fsanitize-blacklist=${suppressions_file}
    )
    target_link_libraries(
      ${name} PRIVATE -fsanitize=thread
                      -fsanitize-blacklist=${suppressions_file}
    )
  elseif(SAN)
    target_compile_options(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${suppressions_file}
    )
    target_link_libraries(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${suppressions_file}
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
