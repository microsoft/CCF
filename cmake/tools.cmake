# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

function(add_san name)
  # CCF_PROJECT is defined when building CCF itself, but not when this function
  # is used by downstream applications.
  if(CCF_PROJECT)
    set(
      suppressions_file
      $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/san_common.suppressions>$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/bin/san_common.suppressions>
    )
  else()
    set(suppressions_file ${CCF_DIR}/bin/san_common.suppressions)
  endif()
  if(TSAN)
    target_compile_options(
      ${name}
      PRIVATE -fsanitize=thread -fsanitize-blacklist=${suppressions_file}
    )
    target_link_libraries(
      ${name}
      PRIVATE -fsanitize=thread -fsanitize-blacklist=${suppressions_file}
    )
  elseif(SAN)
    target_compile_options(
      ${name}
      PRIVATE
        -fsanitize=undefined,address
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
        -fno-sanitize=function
        -fsanitize-blacklist=${suppressions_file}
    )
    target_link_libraries(
      ${name}
      PRIVATE
        -fsanitize=undefined,address
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
        -fno-sanitize=function
        -fsanitize-blacklist=${suppressions_file}
    )
  endif()
endfunction()

function(add_hardening name)
  if(NOT CCF_ENABLE_RELEASE_HARDENING)
    return()
  endif()

  include(CheckCompilerFlag)
  include(CheckLinkerFlag)

  set(
    release_configuration
    "$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>"
  )

  foreach(lang C CXX)
    foreach(
      flag
      IN
      ITEMS
        "-fstack-protector-strong"
        "-D_FORTIFY_SOURCE=2"
        "-fstack-clash-protection"
    )
      string(MAKE_C_IDENTIFIER "${lang}_${flag}" flag_id)
      set(supported_var "CCF_${flag_id}_SUPPORTED")
      check_compiler_flag(${lang} "${flag}" ${supported_var})
      if(${supported_var})
        target_compile_options(
          ${name}
          PRIVATE
            "$<$<AND:${release_configuration},$<COMPILE_LANGUAGE:${lang}>>:${flag}>"
        )
      endif()
    endforeach()
  endforeach()

  # Static, object, and interface libraries do not perform a link step here, but
  # compile hardening still applies to their object files.
  get_target_property(target_type ${name} TYPE)
  if(
    target_type STREQUAL "STATIC_LIBRARY"
    OR target_type STREQUAL "OBJECT_LIBRARY"
    OR target_type STREQUAL "INTERFACE_LIBRARY"
  )
    return()
  endif()

  foreach(lang C CXX)
    foreach(flag IN ITEMS "LINKER:-z,relro" "LINKER:-z,now")
      string(MAKE_C_IDENTIFIER "${lang}_${flag}" flag_id)
      set(supported_var "CCF_${flag_id}_SUPPORTED")
      check_linker_flag(${lang} "${flag}" ${supported_var})
      if(${supported_var})
        target_link_options(
          ${name}
          PRIVATE
            "$<$<AND:${release_configuration},$<LINK_LANGUAGE:${lang}>>:${flag}>"
        )
      endif()
    endforeach()
  endforeach()
endfunction()

function(add_tidy name)
  set_target_properties(
    ${name}
    PROPERTIES
      C_CLANG_TIDY "${CLANG_TIDY_EXE}"
      CXX_CLANG_TIDY "${CLANG_TIDY_EXE}"
  )
endfunction()

separate_arguments(
  COVERAGE_FLAGS
  UNIX_COMMAND
  "-fprofile-instr-generate -fcoverage-mapping"
)
separate_arguments(
  COVERAGE_LINK
  UNIX_COMMAND
  "-fprofile-instr-generate -fcoverage-mapping"
)

function(enable_coverage name)
  if(COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
    set_property(GLOBAL APPEND PROPERTY CCF_COVERAGE_TARGETS ${name})
  endif()
endfunction()
