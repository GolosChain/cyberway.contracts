add_contract(cyber.box cyber.box ${CMAKE_CURRENT_SOURCE_DIR}/src/cyber.box.cpp)
install_contract(cyber.box)

target_include_directories(cyber.box.wasm
   PUBLIC 
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../cyber.token/include
   ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_target_properties(cyber.box.wasm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
