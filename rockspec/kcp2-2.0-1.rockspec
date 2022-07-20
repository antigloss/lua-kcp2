package = "kcp2"
version = "2.0-1"
source = {
   url = "git@git.gametaptap.com:inapp-booster/server/lua-kcp2.git",
   tag = "master"
}
description = {
   summary = "Lua bindings for KCP (Dual channel version)",
   detailed = "",
   homepage = "https://git.gametaptap.com/inapp-booster/server/lua-kcp2",
   license = "MIT"
}
dependencies = {
   "lua >= 5.3"
}
build = {
   type = "cmake",
   variables = {
     CMAKE_BUILD_TYPE = "Release",
     CMAKE_INSTALL_PREFIX = "$(PREFIX)"
   },
}