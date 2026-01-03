cmake_minimum_required(VERSION 3.14)
project(binary_protocol_analyzer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic)

set(SOURCES
    src/main.cpp
    src/protocol_parser.cpp
    src/packet_analyzer.cpp
    src/hexdump.cpp
)

set(HEADERS
    src/protocol_parser.h
    src/packet_analyzer.h
    src/hexdump.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)

enable_testing()

add_executable(test_parser tests/test_parser.cpp src/protocol_parser.cpp src/packet_analyzer.cpp src/hexdump.cpp)
target_include_directories(test_parser PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_parser PRIVATE UNIT_TEST)

add_test(NAME ProtocolParserTest COMMAND test_parser)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
