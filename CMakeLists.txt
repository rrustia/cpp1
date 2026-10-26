cmake_minimum_required(VERSION 3.20)
project(private_data_app LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# I use FetchContent so this project can build without manually downloading headers.
FetchContent_Declare(
  cpp_httplib
  URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.17.3.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_Declare(
  sqlite3_amalgamation
  URL https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(cpp_httplib nlohmann_json sqlite3_amalgamation)

set(SQLITE3_AMALGAMATION_DIR
  ${sqlite3_amalgamation_SOURCE_DIR}/sqlite-amalgamation-3460000
)

add_library(sqlite3 STATIC
  ${SQLITE3_AMALGAMATION_DIR}/sqlite3.c
)
target_include_directories(sqlite3 PUBLIC
  ${SQLITE3_AMALGAMATION_DIR}
)

add_library(httplib_header INTERFACE)
target_include_directories(httplib_header INTERFACE
  ${cpp_httplib_SOURCE_DIR}/cpp-httplib-0.17.3
)

add_library(nlohmann_json_header INTERFACE)
target_include_directories(nlohmann_json_header INTERFACE
  ${nlohmann_json_SOURCE_DIR}/json-3.11.3/include
)

add_executable(private_data_app
  src/main.cpp
  src/database.cpp
  src/auth.cpp
)

target_include_directories(private_data_app PRIVATE src)

target_link_libraries(private_data_app
  PRIVATE
    sqlite3
    httplib_header
    nlohmann_json_header
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
  target_link_libraries(private_data_app PRIVATE OpenSSL::Crypto)
endif()

if(APPLE)
  # I link Security because I rely on CommonCrypto for SHA256 hashing on macOS.
  target_link_libraries(private_data_app PRIVATE "-framework Security")
endif()

if(WIN32)
  target_link_libraries(private_data_app PRIVATE bcrypt)
endif()
