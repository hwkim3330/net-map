cmake_minimum_required(VERSION 3.10)
project(net-map C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Platform detection
if(WIN32)
    message(STATUS "Building for Windows")
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)

    # Npcap SDK path (adjust as needed)
    set(NPCAP_SDK "C:/npcap-sdk" CACHE PATH "Npcap SDK path")
    if(EXISTS ${NPCAP_SDK})
        include_directories(${NPCAP_SDK}/Include)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            link_directories(${NPCAP_SDK}/Lib/x64)
        else()
            link_directories(${NPCAP_SDK}/Lib)
        endif()
    endif()

    set(PCAP_LIB wpcap Packet)
    set(PLATFORM_LIBS ws2_32 iphlpapi)
    set(PLATFORM_SRC src/platform/platform_win.c)
else()
    message(STATUS "Building for Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    include_directories(${PCAP_INCLUDE_DIRS})

    set(PCAP_LIB ${PCAP_LIBRARIES})
    set(PLATFORM_LIBS pthread)
    set(PLATFORM_SRC src/platform/platform_linux.c)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib
)

# Source files
set(CORE_SRC
    src/core/capture.c
    src/core/parser.c
    src/core/buffer.c
)

set(WEB_SRC
    src/web/server.c
    src/web/api.c
    src/web/websocket.c
)

set(LIB_SRC
    lib/mongoose.c
    lib/cJSON.c
)

# Main executable
add_executable(net-map
    src/main.c
    ${CORE_SRC}
    ${WEB_SRC}
    ${PLATFORM_SRC}
    ${LIB_SRC}
)

target_link_libraries(net-map
    ${PCAP_LIB}
    ${PLATFORM_LIBS}
)

# Install
install(TARGETS net-map RUNTIME DESTINATION bin)
install(DIRECTORY src/web/static/ DESTINATION share/net-map/static)
