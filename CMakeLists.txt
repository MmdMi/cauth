cmake_minimum_required(VERSION 3.20)
project(cauth VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(cauth
    src/main.c
    src/base32.c
    src/totp.c
    src/memzero.c
    src/crypto.c
    src/vault.c
)

target_include_directories(cauth PRIVATE include)
target_link_libraries(cauth PRIVATE OpenSSL::Crypto)

target_compile_options(cauth PRIVATE
    -Wall -Wextra -Werror -O2 -fstack-protector-all
    -D_FORTIFY_SOURCE=2
)

add_executable(test_cauth
    test/test_cauth.c
    src/base32.c
    src/totp.c
    src/memzero.c
    src/crypto.c
    src/vault.c
)

target_include_directories(test_cauth PRIVATE include)
target_link_libraries(test_cauth PRIVATE OpenSSL::Crypto)

target_compile_options(test_cauth PRIVATE
    -Wall -Wextra -Werror -O2 -fstack-protector-all
    -D_FORTIFY_SOURCE=2
)
