cmake_minimum_required(VERSION 3.25)
project(DesfireCMAC)

set(CMAKE_CXX_STANDARD 17)

add_executable(DesfireCMAC

        # INCLUDE
        include/aes/AES.cpp
        include/aes/AES.h
        include/cmac/CMAC.cpp
        include/cmac/CMAC.h

        # MAIN
        src/main.cpp

)
