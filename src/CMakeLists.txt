SET(SourceFiles
  packet_relay.cpp
)

add_executable (packet_relay ${SourceFiles})
target_link_libraries (packet_relay owl-common owl-solver pthread)

INSTALL(TARGETS packet_relay RUNTIME DESTINATION bin/owl)
