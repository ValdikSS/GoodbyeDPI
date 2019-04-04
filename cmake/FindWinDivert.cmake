#This is free and unencumbered software released into the public domain.
#Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.
#In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at large and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#For more information, please refer to <https://unlicense.org/>
include(ExternalProject)

set(WinDivert_INCLUDE_DIR_DOC "The dir where WinDivert headers reside")
set(WinDivert_LIBRARY_PATH_DOC "The path to WinDivert library")

find_path(WinDivert_INCLUDE_DIR windivert.h "${CMAKE_SOURCE_DIR}/WinDivert/include" DOC ${WinDivert_INCLUDE_DIR_DOC})
find_library(WinDivert_LIBRARY_PATH NAMES WinDivert.dll PATHS "${CMAKE_SOURCE_DIR}/WinDivert/${CMAKE_SYSTEM_PROCESSOR}/" DOC ${WinDivert_LIBRARY_PATH_DOC})

if(WinDivert_LIBRARY_PATH MATCHES "WinDivert_LIBRARY_PATH-NOTFOUND")
    if(PACKAGE_FIND_VERSION)
    else(PACKAGE_FIND_VERSION)
        set(PACKAGE_FIND_VERSION "1.4.3")
    endif(PACKAGE_FIND_VERSION)

    set(WinDivert_Dev_SCM_name "basil00")
    set(WinDivert_Dev_SCM_repo_name "Divert")
    set(WinDivert_download_URI "https://github.com/${WinDivert_Dev_SCM_name}/${WinDivert_Dev_SCM_repo_name}/releases/download/v${PACKAGE_FIND_VERSION}/WinDivert-${PACKAGE_FIND_VERSION}-A.zip")
    ExternalProject_Add(WinDivert
        URL ${WinDivert_download_URI}
        UPDATE_COMMAND ""
        PATCH_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        TEST_COMMAND ""
    )
    ExternalProject_Get_Property(WinDivert SOURCE_DIR)
    set(WinDivert_INCLUDE_DIR "${SOURCE_DIR}/include" CACHE PATH ${WinDivert_INCLUDE_DIR_DOC} FORCE)
    set(WinDivert_LIBRARY_PATH "${SOURCE_DIR}/${CMAKE_SYSTEM_PROCESSOR}/WinDivert.dll" CACHE FILEPATH ${WinDivert_INCLUDE_DIR_DOC} FORCE)
    message(STATUS "WinDivert not found, scheduled downloading prebuilt version from ${WinDivert_download_URI}. The contents will be unpacked to ${SOURCE_DIR}")
    add_custom_command(OUTPUT "${WinDivert_INCLUDE_DIR}" "${WinDivert_LIBRARY_PATH}" DEPENDS WinDivert COMMAND "")
endif()
