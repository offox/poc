cmake_minimum_required(VERSION 3.14)
project(opus_stereo_encoder_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(opus CONFIG QUIET)
find_package(Opus CONFIG QUIET)

add_executable(opus_streamer
    src/main.cpp
)

if(TARGET opus::opus)
    target_link_libraries(opus_streamer PRIVATE opus::opus)
elseif(TARGET Opus::opus)
    target_link_libraries(opus_streamer PRIVATE Opus::opus)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPUS REQUIRED opus)
    target_include_directories(opus_streamer PRIVATE ${OPUS_INCLUDE_DIRS})
    target_link_libraries(opus_streamer PRIVATE ${OPUS_LIBRARIES})
    target_compile_options(opus_streamer PRIVATE ${OPUS_CFLAGS_OTHER})
endif()
