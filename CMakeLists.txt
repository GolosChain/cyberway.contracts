cmake_minimum_required(VERSION 3.5)
project(cyberway_contracts VERSION 1.5.1)

set(CYBERWAY_CDT_VERSION_MIN "1.6.4")
set(CYBERWAY_CDT_VERSION_SOFT_MAX "1.8")
#set(CYBERWAY_CDT_VERSION_HARD_MAX "")

find_package(cyberway.cdt)

### Check the version of eosio.cdt
set(VERSION_MATCH_ERROR_MSG "")
CYBERWAY_CHECK_VERSION(VERSION_OUTPUT "${CYBERWAY_CDT_VERSION}"
                                   "${CYBERWAY_CDT_VERSION_MIN}"
                                   "${CYBERWAY_CDT_VERSION_SOFT_MAX}"
                                   "${CYBERWAY_CDT_VERSION_HARD_MAX}"
                                   VERSION_MATCH_ERROR_MSG)
MESSAGE(STATUS " -- ${VERSION_MATCH_ERROR_MSG}")
if(VERSION_OUTPUT STREQUAL "MATCH")
   message(STATUS "Using cyberway.cdt version ${CYBERWAY_CDT_VERSION}")
elseif(VERSION_OUTPUT STREQUAL "WARN")
   message(WARNING "Using cyberway.cdt version ${CYBERWAY_CDT_VERSION} even though it exceeds the maximum supported version of ${CYBERWAY_CDT_VERSION_SOFT_MAX}; continuing with configuration, however build may fail.\nIt is recommended to use cyberway.cdt version ${CYBERWAY_CDT_VERSION_SOFT_MAX}.x")
else() # INVALID OR MISMATCH
   message(FATAL_ERROR "Found cyberway.cdt version ${CYBERWAY_CDT_VERSION} but it does not satisfy version requirements: ${VERSION_MATCH_ERROR_MSG}\nPlease use cyberway.cdt version ${CYBERWAY_CDT_VERSION_SOFT_MAX}.x")
endif(VERSION_OUTPUT STREQUAL "MATCH")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(TEST_BUILD_TYPE "Debug")
   set(CMAKE_BUILD_TYPE "Release")
else()
   set(TEST_BUILD_TYPE ${CMAKE_BUILD_TYPE})
endif()

macro(add_contract_with_abi TARGET ABIFILE)
   add_executable( ${TARGET}.wasm ${ARGN} )
   configure_file(${ABIFILE} ${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.abi COPYONLY)
   install (TARGETS ${TARGET}.wasm DESTINATION ${CMAKE_INSTALL_PREFIX}/${TARGET}/)
   install (FILES ${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.abi DESTINATION ${CMAKE_INSTALL_PREFIX}/${TARGET}/)
endmacro()

add_subdirectory(cyber.bios)
add_subdirectory(cyber.msig)
add_subdirectory(cyber.token)
add_subdirectory(cyber.domain)
add_subdirectory(cyber.stake)
add_subdirectory(cyber.govern)
add_subdirectory(cyber.rejector)
add_subdirectory(cyber.incomereject)

if (APPLE)
   set(OPENSSL_ROOT "/usr/local/opt/openssl")
elseif (UNIX)
   set(OPENSSL_ROOT "/usr/include/openssl")
endif()
set(SECP256K1_ROOT "/usr/local")

include(UnitTestsExternalProject.txt)
