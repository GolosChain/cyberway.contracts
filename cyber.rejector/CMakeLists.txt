add_contract_with_checked_abi(cyber.rejector cyber.rejector cyber.rejector.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.rejector.cpp)
install_contract(cyber.rejector)

target_include_directories(cyber.rejector.wasm
   PUBLIC 
   ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(cyber.rejector.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
