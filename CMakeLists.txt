cmake_minimum_required(VERSION 3.10)
project(GlobVPN)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

# Для OpenSSL (опционально, для реального шифрования)
# find_package(OpenSSL REQUIRED)

add_executable(globvpn 
    globvpn.cpp 
    main.cpp
)

target_link_libraries(globvpn ${OPENSSL_LIBRARIES} pthread)


# Платформозависимые библиотеки
if(WIN32)
    target_link_libraries(globvpn ws2_32)
else()
    target_link_libraries(globvpn pthread)
endif()

# Копирование config.json в директорию сборки
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})