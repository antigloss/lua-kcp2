# lua-kcp2: Lua bindings for KCP (Dual channel version)
cmake_minimum_required(VERSION 3.1)
project(kcp2 VERSION 2.0 LANGUAGES C)

add_library(kcp2 MODULE "")

# third party
find_package(Lua)

# environment
set_target_properties(kcp2 PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
set_target_properties(kcp2 PROPERTIES PREFIX "")

file(GLOB_RECURSE
        SRC_FILES
        "kcp/*.c"
        "lua_bindings/*.c")

# generate lib
target_include_directories(kcp2 PRIVATE ${LUA_INCLUDE_DIR} ./)
target_sources(kcp2 PRIVATE ${SRC_FILES})
target_link_libraries(kcp2 ${LUA_LIBRARIES})

# install lib
install(TARGETS kcp2 DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")