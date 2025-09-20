cmake_minimum_required(VERSION 3.15)
project(webrtc_server LANGUAGES CXX)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

add_executable(server src/main.cpp)

target_link_libraries(server PRIVATE CONAN_PKG::libdatachannel CONAN_PKG::openssl)

set_target_properties(server PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
