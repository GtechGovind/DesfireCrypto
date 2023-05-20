cmake_minimum_required(VERSION 3.25)
project(DesfireCrypto)

set(CMAKE_CXX_STANDARD 17)

add_executable(DesfireCrypto

        # INCLUDE
        include/aes/AES.cpp
        include/aes/AES.h
        include/desfire_crypto/DesfireCrypto.cpp
        include/desfire_crypto/DesfireCrypto.h

        # MAIN
        src/main.cpp

)
