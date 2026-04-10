cmake_minimum_required(VERSION 3.10)
project(GlobVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

add_executable(globvpn 
    globvpn.cpp 
    main.cpp
)

target_include_directories(globvpn PRIVATE .)

if(WIN32)
    target_link_libraries(globvpn ws2_32)
else()
    target_link_libraries(globvpn pthread)
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})