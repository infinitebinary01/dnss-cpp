cmake_minimum_required(VERSION 3.15)
project(dnss VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Detect io_uring support
include(CheckIncludeFile)
check_include_file("linux/io_uring.h" HAS_IO_URING)

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

set(SOURCES
    src/main.cpp
    src/caching_resolver.cpp
    src/dns_server.cpp
    src/https_server.cpp
    src/http_resolver.cpp
    src/domain_map.cpp
    src/dns_protocol.cpp
    src/perf_monitor.cpp
    src/auto_tuner.cpp
    src/monitor_server.cpp
    src/connection_controller.cpp
)

set(HEADERS
    src/dns_protocol.hpp
    src/resolver.hpp
    src/caching_resolver.hpp
    src/dns_server.hpp
    src/https_server.hpp
    src/http_resolver.hpp
    src/domain_map.hpp
    src/logger.hpp
    src/perf_monitor.hpp
    src/auto_tuner.hpp
    src/monitor_server.hpp
    src/connection_controller.hpp
)

add_executable(dnss ${SOURCES} ${HEADERS})

target_include_directories(dnss PRIVATE src ${Boost_INCLUDE_DIRS})

target_link_libraries(dnss PRIVATE
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Enable io_uring if available
if(HAS_IO_URING)
    target_compile_definitions(dnss PRIVATE HAS_IO_URING)
    target_link_libraries(dnss PRIVATE uring)
    message(STATUS "io_uring support enabled")
else()
    message(STATUS "io_uring not available (kernel or headers too old)")
endif()

# SIMD optimizations
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-msse4.2" HAS_SSE42)
if(HAS_SSE42)
    target_compile_options(dnss PRIVATE -msse4.2)
    target_compile_definitions(dnss PRIVATE __SSE4_2__)
    message(STATUS "SSE4.2 SIMD enabled")
endif()

# LTO / optimization
target_compile_options(dnss PRIVATE -O3 -flto -march=native)
target_link_options(dnss PRIVATE -O3 -flto -march=native)

install(TARGETS dnss RUNTIME DESTINATION bin)
