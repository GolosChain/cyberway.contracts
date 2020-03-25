add_contract_with_checked_abi(cyber.incomereject cyber.incomereject cyber.incomereject.abi ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.incomereject.cpp)
install_contract(cyber.incomereject)

target_include_directories(cyber.incomereject.wasm
   PUBLIC 
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.token/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.incomereject.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
