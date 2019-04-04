CMAKE_MINIMUM_REQUIRED(VERSION 3.11)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
include(Hardening)
include(VersionFromGit)
PROJECT(GoodbyeDPI)

set(CMAKE_USE_RELATIVE_PATHS TRUE)

set(PACKAGE_NAME "GoodbyeDPI" CACHE STRING "Program name")
set(PACKAGE_VERSION ${VERSION})
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
getVersionFromGit(GoodbyeDPI "v0.1.5")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darvin")
    set(MACOS TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(WINDOWS TRUE)
endif()

set(Source_dir "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(Utils_dir "${CMAKE_CURRENT_SOURCE_DIR}/src/utils")
set(CMake_Misc_Dir "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

file(GLOB_RECURSE SRCFILES "${Source_dir}/*.c" "${Source_dir}/*.cpp")

find_package(WinDivert REQUIRED)

include_directories(GoodbyeDPI "${WinDivert_INCLUDE_DIR}")

#making resource file
set(rc_script_name "goodbyedpi-rc.rc")
set(rc_script "${Source_dir}/${rc_script_name}")
set(rc_script_proto "${CMake_Misc_Dir}/${rc_script_name}.in")
set(license_file "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
file(READ ${license_file} LICENSE_TEXT)
string(REPLACE "\"" "\"\"" LICENSE_TEXT ${LICENSE_TEXT})
string(REPLACE "\r\n" "\n" LICENSE_TEXT ${LICENSE_TEXT})
string(REPLACE "\n" "\\r\\n" LICENSE_TEXT ${LICENSE_TEXT})
message(STATUS "generating resources: ${rc_script_proto} -> ${rc_script}")
configure_file(${rc_script_proto} ${rc_script})
file(GLOB_RECURSE resource_files "${Source_dir}/*.rc" "${Source_dir}/*.ico")


if(MSVC_IDE)
   file(GLOB_RECURSE HDRFILES "${Source_dir}/*.h")
endif()

# config.h
set(CONFIG_FILENAME "config.h")
set(CONFIG_FILE "${Source_dir}/${CONFIG_FILENAME}")
mark_as_advanced(CONFIG_FILE)
set(CONFIG_FILE_PROTO "${CMake_Misc_Dir}/${CONFIG_FILENAME}.in")

set(GoodbyeDPI_SERVICE_NAME "${PACKAGE_NAME}" CACHE STRING "Service name")

set(GoodbyeDPI_HOST_MAXLEN 253 CACHE INTEGER "Max length of a host")
set(GoodbyeDPI_MAX_FILTERS 4 CACHE INTEGER "Max length of a host")
set(GoodbyeDPI_MAX_PACKET_SIZE 9016 CACHE INTEGER "Max length of a host")
set(GoodbyeDPI_DEBUG ${GoodbyeDPI_DEBUG} CACHE BOOL "Enable debug output")

mark_as_advanced(GoodbyeDPI_SERVICE_NAME, GoodbyeDPI_HOST_MAXLEN)

message(STATUS "generating config: ${CONFIG_FILE_PROTO} -> ${CONFIG_FILE}")
configure_file(${CONFIG_FILE_PROTO} ${CONFIG_FILE})

add_executable(GoodbyeDPI "${SRCFILES}" "${HDRFILES}" "${resource_files}")
target_link_libraries(GoodbyeDPI "${WinDivert_LIBRARY_PATH}")

harden(GoodbyeDPI)
if(MINGW)
    target_link_libraries(GoodbyeDPI "wsock32" "ws2_32" "ssp")
elseif(MSVC)
else()
  message(FATAL_ERROR "The compiler is not supported")
endif()


set(RESOURCE_FILES
  resourcefile.txt
  appresourcedir/appres.txt
)


if(MSVC_IDE)
   source_group("res" FILES  ${resource_files})
endif()

if(MSVC)
  set_source_files_properties(${SRCFILES} PROPERTIES LANGUAGE CXX)
else(MSVC)
  #set_source_files_properties(${SRCFILES} PROPERTIES LANGUAGE CXX)
endif(MSVC)

#target_compile_features(GoodbyeDPI PUBLIC cxx_decltype_auto)