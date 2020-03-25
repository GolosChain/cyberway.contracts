add_contract_with_checked_abi(cyber.token cyber.token cyber.token.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.token.cpp)
install_contract(cyber.token)

target_include_directories(cyber.token.wasm
   PUBLIC 
   ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(cyber.token.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
