CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

project(kcp LANGUAGES C)

include(CTest)
include(GNUInstallDirs)

add_library(kcp STATIC ikcp.c)

install(FILES ikcp.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS kcp
    EXPORT kcp-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT kcp-targets
    FILE kcp-config.cmake
    NAMESPACE kcp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kcp
)
