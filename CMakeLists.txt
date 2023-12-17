cmake_minimum_required(VERSION 3.22)
project(eth-wallet)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED true)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Cryptopp REQUIRED IMPORTED_TARGET libcrypto++)
include_directories(${CRYPTOPP_INCLUDE_DIRS})
link_directories(${CRYPTOPP_LIBRARY_DIRS})

add_executable(${CMAKE_PROJECT_NAME}
  wallet.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME} OpenSSL::SSL PkgConfig::Cryptopp)