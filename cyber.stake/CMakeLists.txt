add_contract_with_checked_abi(cyber.stake cyber.stake cyber.stake.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.stake.cpp)
install_contract(cyber.stake)

target_include_directories(cyber.stake.wasm
   PUBLIC 
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.token/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.stake.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
