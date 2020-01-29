add_contract_with_abi(cyber.btcrelay abi/cyber.btcrelay.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.btcrelay.cpp)
target_include_directories(cyber.btcrelay.wasm
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.btcrelay/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.btcrelay.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
