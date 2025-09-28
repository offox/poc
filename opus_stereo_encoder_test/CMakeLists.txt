cmake_minimum_required(VERSION 3.14)
project(opus_stereo_encoder_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Opus REQUIRED)

add_executable(opus_streamer
    src/main.cpp
)


target_include_directories(opus_streamer PUBLIC ${INCLUDE_DIRS})

target_link_libraries(opus_streamer Opus::opus)
