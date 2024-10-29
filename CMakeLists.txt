project(unix_ipc)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(ipc-x ipc_main.c)
target_compile_options(ipc-x PRIVATE -msse2 -Oz -ffast-math)

#add_executable(ipcx-client client.c)
#target_compile_options(ipcx-client PRIVATE -Oz -ffast-math)