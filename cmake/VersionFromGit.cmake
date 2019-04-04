#This is free and unencumbered software released into the public domain.
#Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.
#In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at large and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#For more information, please refer to <https://unlicense.org/>

FIND_PACKAGE(Git)
function(getVersionFromGit variablesPrefix defaultVersion)
  if(GIT_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} describe --dirty --long --tags
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      OUTPUT_VARIABLE VERSION_FROM_GIT
      RESULT_VARIABLE GIT_RESULT
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT GIT_RESULT EQUAL 0)
      message(WARNING "git returned error ${VERSION_FROM_GIT}")
      set(VERSION_FROM_GIT "unknown")
    endif()
  else(GIT_FOUND)
    set(VERSION_FROM_GIT ${defaultVersion})
  endif(GIT_FOUND)


  string(REGEX MATCH "^v?[0-9]+(\\.[0-9]+)+" VERSION ${VERSION_FROM_GIT})
  string(REGEX MATCHALL "[0-9]+" PARSED_VER ${VERSION})

  list(LENGTH PARSED_VER PARSED_VER_LEN)
  if(PARSED_VER_LEN GREATER 0)
    list(GET PARSED_VER 0 VERSION_MAJOR)
  else()
    set(VERSION_MAJOR 0)
  endif()
  if(PARSED_VER_LEN GREATER 1)
    list(GET PARSED_VER 1 VERSION_MINOR)
  else()
    set(VERSION_MINOR 0)
  endif()
  if(PARSED_VER_LEN GREATER 2)
    list(GET PARSED_VER 2 VERSION_PATCH)
  else()
    set(VERSION_PATCH 0)
  endif()
  if(PARSED_VER_LEN GREATER 3)
    list(GET PARSED_VER 3 VERSION_TWEAK)
  else()
    set(VERSION_TWEAK 0)
  endif()
  set(VERSION_MAJOR ${VERSION_MAJOR} CACHE INTERNAL "Major version number")
  set(VERSION_MINOR ${VERSION_MINOR} CACHE INTERNAL "Minor version number")
  set(VERSION_PATCH ${VERSION_PATCH} CACHE INTERNAL "Patch version number")
  set(VERSION_TWEAK ${VERSION_TWEAK} CACHE INTERNAL "Tweak version number")

  set(VERSION_BIN "${VERSION_MAJOR}${VERSION_MINOR}${VERSION_PATCH}" CACHE INTERNAL "Version number as a single number")
  message(STATUS "${variablesPrefix} version: ${VERSION}")
  message(STATUS "${variablesPrefix} bin version: ${VERSION_BIN}")

  if(GIT_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%ct
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      OUTPUT_VARIABLE COMPTIME
      RESULT_VARIABLE GIT_RESULT
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT GIT_RESULT EQUAL 0)
      set(${${variablesPrefix}_COMPTIME} "0000000000" CACHE INTERNAL "Compilation time")
    endif()

    execute_process(
      COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%D
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      OUTPUT_VARIABLE VERSION_EXPORT
      RESULT_VARIABLE GIT_RESULT
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT GIT_RESULT EQUAL 0)
      set(VERSION_EXPORT "HEAD -> master" CACHE INTERNAL)
    endif()
  else(GIT_FOUND)
    set(${${variablesPrefix}_COMPTIME} "0000000000")
    set(VERSION_EXPORT "HEAD -> master" CACHE INTERNAL)
  endif(GIT_FOUND)
  set(${variablesPrefix}_VERSION "${VERSION_EXPORT} ${VERSION_FROM_GIT}" CACHE INTERNAL "Project's version from Git")
  message(STATUS "version tag: ${${variablesPrefix}_VERSION}")
endfunction()