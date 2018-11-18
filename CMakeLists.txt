cmake_minimum_required(VERSION 3.12)
project(JumpUpCamp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap)
set(SOURCE_FILES ping-packet.c)


add_executable(JumpUpCamp ${SOURCE_FILES})

target_link_libraries(JumpUpCamp "${PCAP_LIBRARY}")