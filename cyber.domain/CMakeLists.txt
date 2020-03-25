add_contract_with_checked_abi(cyber.domain cyber.domain cyber.domain.abi ${CMAKE_CURRENT_SOURCE_DIR}/cyber.domain.cpp)
install_contract(cyber.domain)

target_include_directories(cyber.domain.wasm
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.token/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.domain.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
