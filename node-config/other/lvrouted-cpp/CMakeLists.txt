project(lvrouted)
cmake_minimum_required(VERSION 2.8)

add_definitions(-std=c++17 -Wall -fno-rtti -ggdb)
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
execute_process(
        COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions("-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")
add_executable(lvrouted
    src/common.cpp
    src/common.hpp
    src/lvrouted.cpp
    src/MAC.hpp
    src/MAC.cpp
    src/Route.hpp
    src/Route.cpp
    src/Iface.hpp
    src/Iface.cpp
    src/Tree.hpp
    src/Tree.cpp
    src/Neighbor.hpp
    src/Neighbor.cpp
)
target_link_libraries(lvrouted
    crypto
)
