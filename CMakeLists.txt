# CMakeLists.txt - 网络嗅探器构建配置
# 使用 libpcap + ncurses (TUI)，纯 C 实现
cmake_minimum_required(VERSION 3.10)
project(ucassniffer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 警告选项
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# 依赖：libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# ncurses：macOS 系统自带，Linux 通常也有
find_library(NCURSES_LIB ncurses)
if(NOT NCURSES_LIB)
    message(FATAL_ERROR "ncurses library not found")
endif()

# 源文件
set(SNIFFER_SOURCES
    src/main.c
    src/packet.c
    src/capture.c
    src/filter.c
    src/stream.c
    src/dissect/dissect.c
    src/dissect/ethernet.c
    src/dissect/arp.c
    src/dissect/ip.c
    src/dissect/icmp.c
    src/dissect/tcp.c
    src/dissect/udp.c
    src/dissect/http.c
    src/dissect/dns.c
    src/ui/ui.c
)

add_executable(${PROJECT_NAME} ${SNIFFER_SOURCES})

# 包含路径与链接库
target_include_directories(${PROJECT_NAME} PRIVATE
    ${PCAP_INCLUDE_DIRS}
    src
)

target_link_libraries(${PROJECT_NAME}
    ${PCAP_LIBRARIES}
    ${NCURSES_LIB}
    pthread
)

# 安装（可选）
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
