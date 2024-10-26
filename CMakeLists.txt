project(unix_ipc)

add_executable(ipcx-server server.c)
target_compile_options(ipcx-server PRIVATE -Oz -ffast-math -g)

add_executable(ipcx-client client.c)
target_compile_options(ipcx-client PRIVATE -Oz -ffast-math -g)