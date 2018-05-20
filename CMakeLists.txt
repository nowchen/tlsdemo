cmake_minimum_required(VERSION 3.10)

project(tls_server)

add_executable(server server.c)
add_compile_options("-ggdb")
target_link_libraries(server ssl crypto)

add_executable(client client.c)
target_link_libraries(client ssl crypto)