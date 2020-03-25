add_contract_with_checked_abi(cyber.govern cyber.govern cyber.govern.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.govern.cpp)
install_contract(cyber.govern)

target_include_directories(cyber.govern.wasm
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.token/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.stake/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.govern.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
