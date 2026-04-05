cmake_minimum_required(VERSION 4.3)

project(unix_ipc)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(ipc-x ipc_main.c)
target_compile_options(ipc-x PRIVATE -msse4.2 -O2)
