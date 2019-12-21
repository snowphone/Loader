project(Loader)
cmake_minimum_required(VERSION 3.10)

set( CMAKE_VERBOSE_MAKEFILE false )
set(CMAKE_C_FLAGS "-std=gnu99  -Werror")
set(CMAKE_BUILD_TYPE Debug)

add_executable(apager src/loader.c src/common.c src/main.c)
add_executable(dpager src/demand_loader.c src/common.c src/main.c)

add_compile_options( -g -Wall )
