cmake_minimum_required(VERSION 3.25)
project(DesfireCrypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(desfire_crypto
        include/aes/AES.cpp
        include/desfire_crypto/DesfireCrypto.cpp
)
target_include_directories(desfire_crypto PUBLIC include)

add_executable(DesfireCrypto src/main.cpp)
target_link_libraries(DesfireCrypto PRIVATE desfire_crypto)

include(CTest)
if(BUILD_TESTING)
    add_executable(desfire_crypto_tests tests/desfire_crypto_test.cpp)
    target_link_libraries(desfire_crypto_tests PRIVATE desfire_crypto)
    add_test(NAME desfire_crypto_tests COMMAND desfire_crypto_tests)
endif()
